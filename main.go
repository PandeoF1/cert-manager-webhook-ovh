package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/ovh/go-ovh/ovh"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	logf.Log.Info("Webhook starting...")

	if GroupName == "" {
		logf.Log.Error(nil, "GROUP_NAME environment variable must be specified")
		panic("GROUP_NAME must be specified")
	}

	logf.Log.Info("Webhook configuration", "groupName", GroupName)

	// This will register our ovh DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	logf.Log.Info("Registering OVH DNS provider solver and starting webhook server")
	cmd.RunWebhookServer(GroupName,
		&ovhDNSProviderSolver{},
	)
}

// ovhDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type ovhDNSProviderSolver struct {
	client *kubernetes.Clientset
}

// ovhDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type ovhDNSProviderConfig struct {
	Endpoint             string                   `json:"endpoint"`
	ApplicationKeyRef    corev1.SecretKeySelector `json:"applicationKeyRef"`
	ApplicationSecretRef corev1.SecretKeySelector `json:"applicationSecretRef"`
	ConsumerKeyRef       corev1.SecretKeySelector `json:"consumerKeyRef"`
}

type ovhZoneStatus struct {
	IsDeployed bool `json:"isDeployed"`
}

type ovhZoneRecord struct {
	Id        int64  `json:"id,omitempty"`
	FieldType string `json:"fieldType"`
	SubDomain string `json:"subDomain"`
	Target    string `json:"target"`
	TTL       int    `json:"ttl,omitempty"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (s *ovhDNSProviderSolver) Name() string {
	name := "ovh"
	logf.Log.Info("DNS solver name requested", "name", name)
	return name
}

func (s *ovhDNSProviderSolver) validate(cfg *ovhDNSProviderConfig, allowAmbientCredentials bool) error {
	logf.Log.Info("Validating provider config...", 
		"endpoint", cfg.Endpoint,
		"allowAmbientCredentials", allowAmbientCredentials,
		"applicationKeyRef", cfg.ApplicationKeyRef.Name,
		"applicationSecretRef", cfg.ApplicationSecretRef.Name,
		"consumerKeyRef", cfg.ConsumerKeyRef.Name)

	if allowAmbientCredentials {
		// When allowAmbientCredentials is true, OVH client can load missing config
		// values from the environment variables and the ovh.conf files.
		logf.Log.Info("Using ambient credentials mode - allowing empty config values")
		return nil
	}
	if cfg.Endpoint == "" {
		logf.Log.Error(nil, "Validation failed: no endpoint provided in OVH config")
		return errors.New("no endpoint provided in OVH config")
	}
	if cfg.ApplicationKeyRef.Name == "" {
		logf.Log.Error(nil, "Validation failed: no application key provided in OVH config")
		return errors.New("no application key provided in OVH config")
	}
	if cfg.ApplicationSecretRef.Name == "" {
		logf.Log.Error(nil, "Validation failed: no application secret provided in OVH config")
		return errors.New("no application secret provided in OVH config")
	}
	if cfg.ConsumerKeyRef.Name == "" {
		logf.Log.Error(nil, "Validation failed: no consumer key provided in OVH config")
		return errors.New("no consumer key provided in OVH config")
	}
	logf.Log.Info("Provider config validation passed")
	return nil
}

func (s *ovhDNSProviderSolver) ovhClient(ch *v1alpha1.ChallengeRequest) (*ovh.Client, error) {
	logf.Log.Info("Starting challenge request...", 
		"resolvedZone", ch.ResolvedZone,
		"resolvedFQDN", ch.ResolvedFQDN,
		"resourceNamespace", ch.ResourceNamespace,
		"allowAmbientCredentials", ch.AllowAmbientCredentials)
	
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		logf.Log.Error(err, "Failed to load configuration from challenge request")
		return nil, err
	}

	logf.Log.Info("Configuration loaded successfully", "endpoint", cfg.Endpoint)

	err = s.validate(&cfg, ch.AllowAmbientCredentials)
	if err != nil {
		logf.Log.Error(err, "Configuration validation failed")
		return nil, err
	}

	logf.Log.Info("Retrieving secrets for OVH client authentication")
	applicationKey, err := s.secret(cfg.ApplicationKeyRef, ch.ResourceNamespace)
	if err != nil {
		logf.Log.Error(err, "Failed to retrieve application key secret", 
			"secretName", cfg.ApplicationKeyRef.Name,
			"secretKey", cfg.ApplicationKeyRef.Key)
		return nil, err
	}

	applicationSecret, err := s.secret(cfg.ApplicationSecretRef, ch.ResourceNamespace)
	if err != nil {
		logf.Log.Error(err, "Failed to retrieve application secret", 
			"secretName", cfg.ApplicationSecretRef.Name,
			"secretKey", cfg.ApplicationSecretRef.Key)
		return nil, err
	}

	consumerKey, err := s.secret(cfg.ConsumerKeyRef, ch.ResourceNamespace)
	if err != nil {
		logf.Log.Error(err, "Failed to retrieve consumer key secret", 
			"secretName", cfg.ConsumerKeyRef.Name,
			"secretKey", cfg.ConsumerKeyRef.Key)
		return nil, err
	}

	logf.Log.Info("All secrets retrieved successfully, creating OVH client", "endpoint", cfg.Endpoint)
	client, err := ovh.NewClient(cfg.Endpoint, applicationKey, applicationSecret, consumerKey)
	if err != nil {
		logf.Log.Error(err, "Failed to create OVH client", "endpoint", cfg.Endpoint)
		return nil, err
	}

	logf.Log.Info("OVH client created successfully")
	return client, nil
}

func (s *ovhDNSProviderSolver) secret(ref corev1.SecretKeySelector, namespace string) (string, error) {
	logf.Log.Info("Retrieving secret", 
		"secretName", ref.Name,
		"secretKey", ref.Key,
		"namespace", namespace)
	
	if ref.Name == "" {
		logf.Log.Info("Secret name is empty, returning empty string")
		return "", nil
	}

	secret, err := s.client.CoreV1().Secrets(namespace).Get(context.TODO(), ref.Name, metav1.GetOptions{})
	if err != nil {
		logf.Log.Error(err, "Failed to get secret from Kubernetes API", 
			"secretName", ref.Name,
			"namespace", namespace)
		return "", err
	}

	bytes, ok := secret.Data[ref.Key]
	if !ok {
		err := fmt.Errorf("key not found %q in secret '%s/%s'", ref.Key, namespace, ref.Name)
		logf.Log.Error(err, "Secret key not found", 
			"secretName", ref.Name,
			"secretKey", ref.Key,
			"namespace", namespace)
		return "", err
	}
	
	logf.Log.Info("Secret retrieved successfully", 
		"secretName", ref.Name,
		"secretKey", ref.Key,
		"valueLength", len(bytes))
	
	return strings.TrimSuffix(string(bytes), "\n"), nil
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (s *ovhDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	logf.Log.Info("Starting Present operation", 
		"resolvedZone", ch.ResolvedZone,
		"resolvedFQDN", ch.ResolvedFQDN,
		"key", ch.Key)
	
	ovhClient, err := s.ovhClient(ch)
	if err != nil {
		logf.Log.Error(err, "Failed to create OVH client for Present operation")
		return err
	}
	
	domain := util.UnFqdn(ch.ResolvedZone)
	subDomain := getSubDomain(domain, ch.ResolvedFQDN)
	target := ch.Key
	
	logf.Log.Info("Calculated DNS record parameters", 
		"domain", domain,
		"subDomain", subDomain,
		"target", target)
	
	err = addTXTRecord(ovhClient, domain, subDomain, target)
	if err != nil {
		logf.Log.Error(err, "Failed to add TXT record during Present operation")
		return err
	}
	
	logf.Log.Info("Present operation completed successfully")
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (s *ovhDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	logf.Log.Info("Starting CleanUp operation", 
		"resolvedZone", ch.ResolvedZone,
		"resolvedFQDN", ch.ResolvedFQDN,
		"key", ch.Key)
	
	ovhClient, err := s.ovhClient(ch)
	if err != nil {
		logf.Log.Error(err, "Failed to create OVH client for CleanUp operation")
		return err
	}
	
	domain := util.UnFqdn(ch.ResolvedZone)
	subDomain := getSubDomain(domain, ch.ResolvedFQDN)
	target := ch.Key
	
	logf.Log.Info("Calculated DNS record parameters for cleanup", 
		"domain", domain,
		"subDomain", subDomain,
		"target", target)
	
	err = removeTXTRecord(ovhClient, domain, subDomain, target)
	if err != nil {
		logf.Log.Error(err, "Failed to remove TXT record during CleanUp operation")
		return err
	}
	
	logf.Log.Info("CleanUp operation completed successfully")
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (s *ovhDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	logf.Log.Info("Initializing OVH DNS provider solver", 
		"kubeHost", kubeClientConfig.Host,
		"kubeAPIVersion", kubeClientConfig.APIPath)
	
	client, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		logf.Log.Error(err, "Failed to create Kubernetes client during initialization")
		return err
	}

	s.client = client
	logf.Log.Info("OVH DNS provider solver initialized successfully")
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (ovhDNSProviderConfig, error) {
	logf.Log.Info("Loading configuration from JSON")
	cfg := ovhDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		logf.Log.Info("No configuration provided, using empty config")
		return cfg, nil
	}
	
	logf.Log.Info("Unmarshaling JSON configuration", "configLength", len(cfgJSON.Raw))
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		logf.Log.Error(err, "Failed to decode OVH config from JSON")
		return cfg, fmt.Errorf("error decoding OVH config: %v", err)
	}

	logf.Log.Info("Configuration loaded successfully", 
		"endpoint", cfg.Endpoint,
		"applicationKeyRef", cfg.ApplicationKeyRef.Name,
		"applicationSecretRef", cfg.ApplicationSecretRef.Name,
		"consumerKeyRef", cfg.ConsumerKeyRef.Name)
	return cfg, nil
}

func getSubDomain(domain, fqdn string) string {
	logf.Log.Info("Calculating subdomain", "domain", domain, "fqdn", fqdn)
	
	if idx := strings.Index(fqdn, "."+domain); idx != -1 {
		subDomain := fqdn[:idx]
		logf.Log.Info("Subdomain calculated using domain match", "subDomain", subDomain)
		return subDomain
	}

	subDomain := util.UnFqdn(fqdn)
	logf.Log.Info("Subdomain calculated using UnFqdn", "subDomain", subDomain)
	return subDomain
}

func addTXTRecord(ovhClient *ovh.Client, domain, subDomain, target string) error {
	logf.Log.Info("Starting addTXTRecord operation", 
		"domain", domain,
		"subDomain", subDomain,
		"target", target)
	
	err := validateZone(ovhClient, domain)
	if err != nil {
		logf.Log.Error(err, "Zone validation failed during addTXTRecord")
		return err
	}

	record, err := createRecord(ovhClient, domain, "TXT", subDomain, target)
	if err != nil {
		logf.Log.Error(err, "Failed to create TXT record")
		return err
	}
	
	logf.Log.Info("TXT record created successfully", "recordId", record.Id)
	
	err = refreshRecords(ovhClient, domain)
	if err != nil {
		logf.Log.Error(err, "Failed to refresh records after adding TXT record")
		return err
	}
	
	logf.Log.Info("addTXTRecord operation completed successfully")
	return nil
}

func removeTXTRecord(ovhClient *ovh.Client, domain, subDomain, target string) error {
	logf.Log.Info("Starting removeTXTRecord operation", 
		"domain", domain,
		"subDomain", subDomain,
		"target", target)
	
	ids, err := listRecords(ovhClient, domain, "TXT", subDomain)
	if err != nil {
		logf.Log.Error(err, "Failed to list records during removeTXTRecord")
		return err
	}

	logf.Log.Info("Found records to process", "recordCount", len(ids), "recordIds", ids)

	deletedCount := 0
	for _, id := range ids {
		logf.Log.Info("Processing record for potential deletion", "recordId", id)
		
		record, err := getRecord(ovhClient, domain, id)
		if err != nil {
			logf.Log.Error(err, "Failed to get record details", "recordId", id)
			return err
		}
		
		logf.Log.Info("Retrieved record details", 
			"recordId", id,
			"recordTarget", record.Target,
			"expectedTarget", target)
		
		if record.Target != target {
			logf.Log.Info("Record target doesn't match, skipping deletion", 
				"recordId", id,
				"recordTarget", record.Target,
				"expectedTarget", target)
			continue
		}
		
		err = deleteRecord(ovhClient, domain, id)
		if err != nil {
			logf.Log.Error(err, "Failed to delete record", "recordId", id)
			return err
		}
		
		deletedCount++
		logf.Log.Info("Record deleted successfully", "recordId", id)
	}

	logf.Log.Info("Record deletion phase completed", "deletedCount", deletedCount)

	err = refreshRecords(ovhClient, domain)
	if err != nil {
		logf.Log.Error(err, "Failed to refresh records after removing TXT record")
		return err
	}
	
	logf.Log.Info("removeTXTRecord operation completed successfully", "deletedRecords", deletedCount)
	return nil
}

func validateZone(ovhClient *ovh.Client, domain string) error {
	logf.Log.Info("Validating OVH zone", "domain", domain)
	
	url := "/domain/zone/" + domain + "/status"
	zoneStatus := ovhZoneStatus{}
	
	logf.Log.Info("Making OVH API call", "method", "GET", "url", url)
	err := ovhClient.Get(url, &zoneStatus)
	if err != nil {
		logf.Log.Error(err, "OVH API call failed", "method", "GET", "url", url)
		return fmt.Errorf("OVH API call failed: GET %s - %v", url, err)
	}
	
	logf.Log.Info("Zone status retrieved", "domain", domain, "isDeployed", zoneStatus.IsDeployed)
	
	if !zoneStatus.IsDeployed {
		err := fmt.Errorf("OVH zone not deployed for domain %s", domain)
		logf.Log.Error(err, "Zone validation failed - zone not deployed", "domain", domain)
		return err
	}

	logf.Log.Info("Zone validation successful", "domain", domain)
	return nil
}

func listRecords(ovhClient *ovh.Client, domain, fieldType, subDomain string) ([]int64, error) {
	logf.Log.Info("Listing DNS records", 
		"domain", domain,
		"fieldType", fieldType,
		"subDomain", subDomain)
	
	url := "/domain/zone/" + domain + "/record?fieldType=" + fieldType + "&subDomain=" + subDomain
	ids := []int64{}
	
	logf.Log.Info("Making OVH API call", "method", "GET", "url", url)
	err := ovhClient.Get(url, &ids)
	if err != nil {
		logf.Log.Error(err, "OVH API call failed", "method", "GET", "url", url)
		return nil, fmt.Errorf("OVH API call failed: GET %s - %v", url, err)
	}
	
	logf.Log.Info("Records listed successfully", 
		"domain", domain,
		"fieldType", fieldType,
		"subDomain", subDomain,
		"recordCount", len(ids),
		"recordIds", ids)
	
	return ids, nil
}

func getRecord(ovhClient *ovh.Client, domain string, id int64) (*ovhZoneRecord, error) {
	logf.Log.Info("Getting DNS record details", "domain", domain, "recordId", id)
	
	url := "/domain/zone/" + domain + "/record/" + strconv.FormatInt(id, 10)
	record := ovhZoneRecord{}
	
	logf.Log.Info("Making OVH API call", "method", "GET", "url", url)
	err := ovhClient.Get(url, &record)
	if err != nil {
		logf.Log.Error(err, "OVH API call failed", "method", "GET", "url", url)
		return nil, fmt.Errorf("OVH API call failed: GET %s - %v", url, err)
	}
	
	logf.Log.Info("Record details retrieved successfully", 
		"domain", domain,
		"recordId", id,
		"fieldType", record.FieldType,
		"subDomain", record.SubDomain,
		"target", record.Target,
		"ttl", record.TTL)
	
	return &record, nil
}

func deleteRecord(ovhClient *ovh.Client, domain string, id int64) error {
	logf.Log.Info("Deleting DNS record", "domain", domain, "recordId", id)
	
	url := "/domain/zone/" + domain + "/record/" + strconv.FormatInt(id, 10)
	
	logf.Log.Info("Making OVH API call", "method", "DELETE", "url", url)
	err := ovhClient.Delete(url, nil)
	if err != nil {
		logf.Log.Error(err, "OVH API call failed", "method", "DELETE", "url", url)
		return fmt.Errorf("OVH API call failed: DELETE %s - %v", url, err)
	}
	
	logf.Log.Info("Record deleted successfully", "domain", domain, "recordId", id)
	return nil
}

func createRecord(ovhClient *ovh.Client, domain, fieldType, subDomain, target string) (*ovhZoneRecord, error) {
	logf.Log.Info("Creating DNS record", 
		"domain", domain,
		"fieldType", fieldType,
		"subDomain", subDomain,
		"target", target)
	
	url := "/domain/zone/" + domain + "/record"
	params := ovhZoneRecord{
		FieldType: fieldType,
		SubDomain: subDomain,
		Target:    target,
		TTL:       60,
	}
	
	logf.Log.Info("Making OVH API call with parameters", 
		"method", "POST",
		"url", url,
		"fieldType", params.FieldType,
		"subDomain", params.SubDomain,
		"target", params.Target,
		"ttl", params.TTL)
	
	record := ovhZoneRecord{}
	err := ovhClient.Post(url, &params, &record)
	if err != nil {
		logf.Log.Error(err, "OVH API call failed", "method", "POST", "url", url)
		return nil, fmt.Errorf("OVH API call failed: POST %s - %v", url, err)
	}

	logf.Log.Info("Record created successfully", 
		"domain", domain,
		"recordId", record.Id,
		"fieldType", record.FieldType,
		"subDomain", record.SubDomain,
		"target", record.Target,
		"ttl", record.TTL)

	return &record, nil
}

func refreshRecords(ovhClient *ovh.Client, domain string) error {
	logf.Log.Info("Refreshing DNS zone records", "domain", domain)
	
	url := "/domain/zone/" + domain + "/refresh"
	
	logf.Log.Info("Making OVH API call", "method", "POST", "url", url)
	err := ovhClient.Post(url, nil, nil)
	if err != nil {
		logf.Log.Error(err, "OVH API call failed", "method", "POST", "url", url)
		return fmt.Errorf("OVH API call failed: POST %s - %v", url, err)
	}

	logf.Log.Info("Zone records refreshed successfully", "domain", domain)
	return nil
}
