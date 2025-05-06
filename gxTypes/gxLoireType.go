/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package gxTypes

import (
	vc "github.com/Posedio/gaia-x-go/verifiableCredentials"
	"time"
)

type URI string

// GaiaXEntity is the root class for Gaia-X entities
type GaiaXEntity struct {
	vc.CredentialSubjectShape
	// A human readable name of the entity
	Name string `json:"schema:name,omitempty"`
	// Description of the entity
	Description string `json:"schema:description,omitempty"`
}

// Address represents a full physical address
type Address struct {
	vc.CredentialSubjectShape
	// Required: Unique code identifying a country
	CountryCode string `json:"gx:countryCode,omitempty,omitzero"`
	// Required: The name of the country
	CountryName string `json:"gx:countryName,omitempty"`
	// GPS in ISO 6709:2008/Cor 1:2009 format
	GPS GPSLocation `json:"gps,omitempty,omitzero"`
	// The street address of a postal address
	StreetAddress string `json:"vcard:street-address,omitempty"`
	// The local postal code of the address
	PostalCode string `json:"vcard:postal-code,omitempty"`
	// The locality (e.g. city or town) associated with the address
	Locality string `json:"vcard:locality,omitempty"`
	// The NUTS2 region code of the geographical location
	Region string `json:"vcard:region,omitempty"`
}

// GPSLocation represents physical GPS coordinates in ISO 6709:2008/Cor 1:2009 format
type GPSLocation struct {
	vc.CredentialSubjectShape
	// Coordinate representing x horizontal position (latitude)
	Latitude string `json:"latitude,omitempty"`
	// Coordinate representing y horizontal position (longitude)
	Longitude string `json:"longitude,omitempty"`
	// Vertical position through height or depth
	Altitude string `json:"altitude,omitempty"`
	// Coordinate Reference System identifier
	CRS string `json:"crs,omitempty"`
}

// GPSUnit defines a geographical point
type GPSUnit struct {
	// Degrees component of coordinate
	Degrees int `json:"degrees"`
	// Minutes component of coordinate
	Minutes int `json:"minutes,omitempty"`
	// Seconds component of coordinate
	Seconds int `json:"seconds,omitempty"`
	// Decimal component of coordinate
	Decimals float64 `json:"decimals,omitempty"`
}

type ResourceInterface interface {
	GetID() string
	GetIdOnlyObject() Resource
}

// Resource is a description of a good or object in the Gaia-X Ecosystem
type Resource struct {
	GaiaXEntity
	// A resolvable link of resources related to an entity and that can exist independently of it
	AggregationOfResources []ResourceInterface `json:"gx:aggregationOfResources,omitempty"`
}

func (r Resource) GetID() string {
	return r.ID
}

func (r Resource) GetIdOnlyObject() Resource {
	rNew := Resource{}
	rNew.ID = r.ID
	rNew.Type = r.Type
	return rNew
}

// VirtualResource represents static data in any form and necessary information
type VirtualResource struct {
	Resource
	// A list of copyright owners either as a free form string or as resolvable link to Gaia-X Credential of participants
	CopyrightOwnedBy []string `json:"gx:copyrightOwnedBy"`
	// A list of SPDX identifiers or URL to document
	License []string `json:"gx:license"`
	// A list of policy expressed using a DSL
	ResourcePolicy []string `json:"gx:resourcePolicy,omitempty"`
}

// PhysicalResource represents a datacenter, bare-metal service, warehouse, plant, etc.
type PhysicalResource struct {
	Resource
	// Required: A list of resolvable links to Gaia-X Credentials of participants maintaining the resource
	MaintainedBy []LegalPerson `json:"gx:maintainedBy,omitempty,omitzero"`
	// A list of resolvable links to Gaia-X Credentials of participant owning the resource
	OwnedBy []LegalPerson `json:"gx:ownedBy,omitempty,omitzero"`
	// A list of resolvable links to Gaia-X Credentials of participant manufacturing the resource
	ManufacturedBy []LegalPerson `json:"gx:manufacturedBy,omitempty,omitzero"`
	// Required: A list of physical locations
	Location []Address `json:"gx:location,omitempty,omitzero"`
	// Information about the energy usage efficiency of the resource
	EnergyUsageEfficiency *EnergyUsageEfficiency `json:"gx:energyUsageEfficiency,omitempty"`
	// Information regarding the water usage effectiveness of the resource
	WaterUsageEffectiveness *WaterUsageEffectiveness `json:"gx:waterUsageEffectiveness,omitempty"`
	// Information on the composition of the energy mix used by the resource
	EnergyMix []EnergyMix `json:"gx:energyMix,omitempty,omitzero"`
}

// SoftwareResource describes an executable program
type SoftwareResource struct {
	VirtualResource
	// Details on checksum of the software
	CheckSum *CheckSum `json:"gx:checkSum,omitempty"`
	// Details with respect to signature of the software
	Signature *Signature `json:"gx:signature,omitempty"`
	// Version of the software
	Version string `json:"gx:version,omitempty"`
	// Software specific patch number describing patch level of the software
	PatchLevel string `json:"gx:patchLevel,omitempty"`
	// Date and time the software was build, formatted according to ISO 8601
	BuildDate time.Time `json:"gx:buildDate,omitempty"`
}

// CodeArtifact represents a piece of software that can be executed by a Compute service
type CodeArtifact struct {
	SoftwareResource
}

// OperatingSystem describes an operating system
type OperatingSystem struct {
	SoftwareResource
	// The common name of the distribution of the operating system
	OSDistribution string `json:"gx:osDistribution"`
}

// Hypervisor describes a hypervisor to provide virtual machines
type Hypervisor struct {
	SoftwareResource
	// The hypervisor type
	HypervisorType string `json:"gx:hypervisorType"`
}

// Device represents hardware or virtualized device properties and capabilities
type Device struct {
	vc.CredentialSubjectShape
	// Vendor of the device
	Vendor string `json:"gx:vendor,omitempty"`
	// Vendor specific generation of the device
	Generation string `json:"gx:generation,omitempty"`
	// Default oversubscription ratio (1.0 means no oversubscription)
	DefaultOversubscriptionRatio int `json:"gx:defaultOversubscriptionRatio,omitempty"`
	// Supported oversubscription ratio
	SupportedOversubscriptionRatio int `json:"gx:supportedOversubscriptionRatio,omitempty"`
}

// CPU represents computational processing unit capabilities
type CPU struct {
	Device
	// Architecture of CPU
	CPUArchitecture string `json:"gx:cpuArchitecture,omitempty"`
	// CPU flags as documented by lscpu
	CPUFlag []string `json:"gx:cpuFlag,omitempty"`
	// Whether simultaneous multithreading is enabled
	SMTEnabled bool `json:"gx:smtEnabled,omitempty"`
	// Number of cores of the CPU
	NumberOfCores int `json:"gx:numberOfCores,omitempty"`
	// Number of threads of the CPU
	NumberOfThreads int `json:"gx:numberOfThreads,omitempty"`
	// Base frequency of the CPU
	BaseFrequency *Frequency `json:"gx:baseFrequency,omitempty"`
	// Boost frequency of the CPU
	BoostFrequency *Frequency `json:"gx:boostFrequency,omitempty"`
	// Last Level Cache size of the CPU
	LastLevelCacheSize *MemorySize `json:"gx:lastLevelCacheSize,omitempty"`
	// CPU Thermal Design Power
	ThermalDesignPower *Power `json:"gx:thermalDesignPower,omitempty"`
}

// GPU represents graphics processing unit capabilities
type GPU struct {
	Device
	// Size of memory of the GPU
	GPUMemory *MemorySize `json:"gx:gpuMemory,omitempty"`
	// Interconnection of multiple GPUs within a server system
	GPUInterconnection string `json:"gx:gpuInterconnection,omitempty"`
	// Number of processing units of the GPU
	GPUProcessingUnits int `json:"gx:gpuProcessingUnits,omitempty"`
	// If true, GPU is provided via passthrough, otherwise GPU is virtualized
	GPUPassthrough bool `json:"gx:gpuPassthrough,omitempty"`
}

// Memory represents RAM capabilities
type Memory struct {
	Device
	// Memory size of RAM
	MemorySize *MemorySize `json:"gx:memorySize"`
	// DRAM technology name defined by JEDEC
	MemoryClass string `json:"gx:memoryClass,omitempty"`
	// Rank defines the number of memory chip banks and the buffering used to access these
	MemoryRank string `json:"gx:memoryRank,omitempty"`
	// Whether error-correction-code is supported by the RAM
	ECCEnabled bool `json:"gx:eccEnabled,omitempty"`
	// If true, encryption of memory at the hardware level is enabled
	HardwareEncryption bool `json:"gx:hardwareEncryption,omitempty"`
}

// Disk represents capabilities of a physical or virtual hard drive
type Disk struct {
	Device
	// The size of the hard drive
	DiskSize *MemorySize `json:"gx:diskSize"`
	// The type of storage drive
	DiskType string `json:"gx:diskType,omitempty"`
	// Type of disk controller the disk is attached to
	DiskBusType string `json:"gx:diskBusType,omitempty"`
}

// QuantityKind is a parent class for all physical quantities kinds
type QuantityKind struct {
	// Value of physical quantity
	Value float64 `json:"qudt:value"`
	// Unit of physical quantity
	Unit string `json:"qudt:unit"`
}

// Frequency represents a frequency quantity
type Frequency struct {
	QuantityKind
}

// MemorySize represents bytes storage capacity
type MemorySize struct {
	QuantityKind
}

// Power represents a power quantity
type Power struct {
	QuantityKind
}

// DataRate represents a data rate quantity
type DataRate struct {
	QuantityKind
}

// Time represents a time quantity
type Time struct {
	QuantityKind
}

// RetentionDuration is specific to data retention timeframes
type RetentionDuration struct {
	Time
}

// FloatPercentage represents a percentage value
type FloatPercentage struct {
	// Percentage value between 0.0 and 100.0
	Value float64 `json:"gx:value"`
}

// Participant represents a legal or natural person in Gaia-X
type Participant struct {
	GaiaXEntity
}

// LegalPerson represents a legal entity identified by a registration number
type LegalPerson struct {
	Participant
	// Required as URI to the VC from the GXDCH, Country's registration number, which identifies one specific entity, provide the link to the vc of the notary endpoint for legal registration number
	RegistrationNumber RegistrationNumber `json:"gx:registrationNumber,omitempty,omitzero"`
	// Required: The full legal address of the organization
	LegalAddress Address `json:"gx:legalAddress,omitempty,omitzero"`
	// Required: Full physical location of the headquarter of the organization
	HeadquartersAddress Address `json:"gx:headquartersAddress,omitempty,omitzero"`
	// List of participants that this entity is a subOrganization of, if any
	ParentOrganizationOf []LegalPerson `json:"gx:parentOrganizationOf,omitempty"`
	// List of participants with a legal mandate on this entity
	SubOrganisationOf []LegalPerson `json:"gx:subOrganisationOf,omitempty"`
	Name              string        `json:"schema:name,omitempty"`
}

// RegistrationNumber is an abstract representation of different types of registration IDs
type RegistrationNumber interface {
	GetType() string
	GetId() string
}

type RegistrationNumberID struct {
	vc.CredentialSubjectShape
}

func (rn RegistrationNumberID) GetType() string {
	return ""
}

func (rn RegistrationNumberID) GetId() string {
	return rn.ID
}

// VatID represents a VAT identification number
type VatID struct {
	GaiaXEntity
	// The VAT identification number
	VatID string `json:"gx:vatID"`
	// The country where the VAT identification number is registered
	CountryCode string `json:"gx:countryCode"`
}

func (v VatID) GetType() string {
	return "gx:vatID"
}

func (v VatID) GetId() string {
	return v.ID
}

// LeiCode represents a Legal Entity Identifier code
type LeiCode struct {
	GaiaXEntity
	// Unique LEI number as defined by https://www.gleif.org
	LeiCode string `json:"schema:leiCode"`
	// The country where the LEI number is registered
	CountryCode string `json:"gx:countryCode"`
	// The country subdivision (state/region) where the LEI number is registered
	SubdivisionCountryCode string `json:"gx:subdivisionCountryCode,omitempty"`
	Type                   string `json:"type,omitempty"`
}

func (l LeiCode) GetType() string {
	return "schema:leiCode"
}

func (l LeiCode) GetId() string {
	return l.ID
}

// EORI represents an Economic Operators Registration and Identification number
type EORI struct {
	GaiaXEntity
	// The Economic Operators Registration and Identification number (EORI)
	Eori string `json:"gx:eori"`
	// The country where the EORI is registered written in plain english
	Country string `json:"gx:country"`
}

func (e EORI) GetType() string {
	return "EORI"
}

func (e EORI) GetId() string {
	return e.ID
}

// EUID represents a European Unique Identifier
type EUID struct {
	GaiaXEntity
	// The European Unique Identifier (EUID) for business registered in BRIS
	Euid string `json:"gx:euid"`
}

func (e EUID) GetType() string {
	return "EUID"
}

func (e EUID) GetId() string {
	return e.ID
}

// TaxID represents a company tax ID
type TaxID struct {
	GaiaXEntity
	// The company tax ID
	TaxId string `json:"schema:taxID"`
}

func (t TaxID) GetType() string {
	return "TaxID"
}

func (t TaxID) GetId() string {
	return t.ID
}

// Image represents a software that can be executed by compute services
type Image struct {
	CodeArtifact
	// Size of the image
	FileSize *MemorySize `json:"gx:fileSize,omitempty"`
	// A resolvable link to Gaia-X credential of operation system offered by this image
	OperatingSystem *OperatingSystem `json:"gx:operatingSystem,omitempty"`
	// Details with respect to CPU capabilities required to run the image
	CPUReq *CPU `json:"gx:cpuReq,omitempty"`
	// Details with respect to GPU capabilities required to run the image
	GPUReq *GPU `json:"gx:gpuReq,omitempty"`
	// Minimal size of RAM required to run the image
	RAMReq *Memory `json:"gx:ramReq,omitempty"`
	// Maximum amount of RAM for the video image
	VideoRAMSize *MemorySize `json:"gx:videoRamSize,omitempty"`
	// Minimal size of root disk required to run the image
	RootDiskReq *Disk `json:"gx:rootDiskReq,omitempty"`
	// Details with respect to encryption of the images
	Encryption *Encryption `json:"gx:encryption,omitempty"`
	// If true, instances of the image are only started with valid signatures
	SecureBoot bool `json:"gx:secureBoot,omitempty"`
	// If true, a virtual performance monitoring unit (vPMU) is enabled in guest
	VPMU bool `json:"gx:vPMU,omitempty"`
	// If true, one queue is set for each virtual CPU
	MultiQueues bool `json:"gx:multiQueues,omitempty"`
	// Details on provider's image update strategy of this image
	UpdateStrategy *UpdateStrategy `json:"gx:updateStrategy,omitempty"`
	// Whether service usage fee includes commercial license
	LicenseIncluded bool `json:"gx:licenseIncluded,omitempty"`
	// Details on maintenance capabilities of vendor of image's operating system
	Maintenance *MaintenanceSubscription `json:"gx:maintenance,omitempty"`
}

// VM_Image represents an image for virtual machines
type VM_Image struct {
	Image
	// Disk format of the VM image
	VMImageDiskFormat string `json:"gx:vmImageDiskFormat,omitempty"`
	// Hypervisor type required by the image
	HypervisorType string `json:"gx:hypervisorType,omitempty"`
	// Type of firmware which which guests are booted
	FirmwareType string `json:"gx:firmwareType,omitempty"`
	// Type of physical phenomena hardware random number generator (RNG) this image prefers
	HwRngTypeOfImage string `json:"gx:hwRngTypeOfImage,omitempty"`
	// Define the action to be performed if server hangs
	WatchDogAction string `json:"gx:watchDogAction,omitempty"`
}

// PXE_Image represents a PXE image for physical machines
type PXE_Image struct {
	Image
	// Disk format. Default "ISO"
	PXEImageDiskFormat string `json:"gx:pxeImageDiskFormat,omitempty"`
}

// ContainerImage represents an image available for containers
type ContainerImage struct {
	Image
	// Container image base software stack
	BaseContainerImage *BaseContainerImage `json:"gx:baseContainerImage"`
	// Container image format
	ContainerFormat string `json:"gx:containerFormat"`
}

// BaseContainerImage represents a set of tags for an image and a repository link
type BaseContainerImage struct {
	// Tag(s) associated with a container image
	ContainerImageTag []string `json:"gx:containerImageTag,omitempty"`
	// Link to the image's repository
	ContainerImageLink vc.URL `json:"gx:containerImageLink"`
}

// Encryption represents encryption capabilities
type Encryption struct {
	vc.CredentialSubjectShape
	// Supported algorithm used to encrypt
	Cipher string `json:"gx:cipher"`
	// Define key management method
	KeyManagement string `json:"gx:keyManagement"`
}

// CheckSum provides details on how to calculate or verify a checksum
type CheckSum struct {
	// Algorithm used to create checksum
	CheckSumCalculation string `json:"gx:checkSumCalculation"`
	// Value of the check sum
	CheckSumValue string `json:"gx:checkSumValue"`
}

// Signature represents a digital signature
type Signature struct {
	// Value of the signature
	SignatureValue string `json:"gx:signatureValue"`
	// Algorithm used to create the hash
	HashAlgorithm string `json:"gx:hashAlgorithm"`
	// Algorithm used to calculate or verify the signature
	SignatureAlgorithm string `json:"gx:signatureAlgorithm"`
}

// UpdateStrategy defines aspects of a provider's image update policy
type UpdateStrategy struct {
	// Frequency in which the provider updates the image on a regular basis
	ReplaceFrequency string `json:"gx:replaceFrequency,omitempty"`
	// Time in hours passed after image's distributor published a critical hot fix
	HotfixHours int `json:"gx:hotfixHours,omitempty"`
	// Defines how long outdated and hidden images are available by its ID
	OldVersionsValidUntil string `json:"gx:oldVersionsValidUntil,omitempty"`
	// Details how long the image will be provided in image catalogue
	ProvidedUntil string `json:"gx:providedUntil,omitempty"`
}

// MaintenanceSubscription represents access to bug fixes, security fixes, and function updates
type MaintenanceSubscription struct {
	// If true, cloud service provider prepared the image to receive fixes and updates
	SubscriptionIncluded bool `json:"gx:subscriptionIncluded,omitempty"`
	// If true, user needs a maintenance subscription account to receive fixes
	SubscriptionRequired bool `json:"gx:subscriptionRequired,omitempty"`
	// Date until vendor of image's operating system promises maintenance at least
	MaintainedUntil time.Time `json:"gx:maintainedUntil,omitempty"`
}

// InstantiationRequirement is a container for service offering instantiation requirements
type InstantiationRequirement struct {
	GaiaXEntity
}

// ServerFlavor describes available hardware configurations
type ServerFlavor struct {
	InstantiationRequirement
	// Capabilities of virtual CPUs available in flavor
	CPU *CpuCapabilities `json:"gx:cpu"`
	// Memory capabilities
	Memory *MemoryCapabilities `json:"gx:memory"`
	// GPU capabilities of the flavor
	GPU *GPU `json:"gx:gpu,omitempty"`
	// Network capabilities of the flavor
	Network string `json:"gx:network,omitempty"`
	// Boot volume capabilities of boot volume of the flavor
	BootVolume *Disk `json:"gx:bootVolume"`
	// Additional volume capabilities of boot volume of the flavor
	AdditionalVolume []Disk `json:"gx:additionalVolume,omitempty"`
	// Details with respect to confidential computing capabilities of the flavor
	ConfidentialComputing *ConfidentialComputing `json:"gx:confidentialComputing,omitempty"`
	// Hypervisor as Gaia-X software resources
	Hypervisor *Hypervisor `json:"gx:hypervisor,omitempty"`
	// If true, hardware-assisted virtualization is enabled for full virtualization
	HardwareAssistedVirtualization bool `json:"gx:hardwareAssistedVirtualization,omitempty"`
	// Type of physical phenomena hardware random number generator (RNG) of this flavor is based on
	HwRngTypeOfFlavor string `json:"gx:hwRngTypeOfFlavor,omitempty"`
}

// CpuCapabilities represents CPU capabilities in a flavor
type CpuCapabilities struct {
	// Hardware capabilities of physical CPU used by given flavor
	PCPU *CPU `json:"gx:pCPU"`
	// Number of virtual CPUs available in given flavor
	VCPUs int `json:"gx:vCPUs"`
	// Overprovisioning ratio defined by division of virtual resource over physical resource
	OverProvisioningRatio float64 `json:"gx:overProvisioningRatio,omitempty"`
}

// MemoryCapabilities represents memory capabilities in a flavor
type MemoryCapabilities struct {
	// Amount of virtual RAM available in given flavor
	Memory *Memory `json:"gx:memory"`
	// Overprovisioning ratio for virtual RAM vs physical RAM
	OverProvisioningRatio float64 `json:"gx:overProvisioningRatio,omitempty"`
}

// ConfidentialComputing represents confidential computing capabilities
type ConfidentialComputing struct {
	// Particular confidential computing technology used by flavors
	Technology string `json:"gx:technology"`
	// Indicates whether confidential server has an associated attestation service
	AttestationServiceURI vc.URL `json:"gx:attestationServiceURI,omitempty"`
}

// ContainerResourceLimits represents resource limits for containers
type ContainerResourceLimits struct {
	InstantiationRequirement
	// CPU requirements
	CPURequirements *CPU `json:"gx:cpuRequirements,omitempty"`
	// Limit to the number of cores usable by a container
	NumberOfCoresLimit int `json:"gx:numberOfCoresLimit,omitempty"`
	// Container memory requirements
	MemoryRequirements *Memory `json:"gx:memoryRequirements,omitempty"`
	// Container memory limits
	MemoryLimit *MemorySize `json:"gx:memoryLimit,omitempty"`
	// GPU requirements
	GPURequirements *GPU `json:"gx:gpuRequirements,omitempty"`
	// GPU number limit
	GPULimit int `json:"gx:gpuLimit,omitempty"`
	// Indicates whether container is of confidential nature
	Confidential bool `json:"gx:confidential"`
	// Details with respect to confidential computing requirements
	ConfidentialComputingTechnology *ConfidentialComputing `json:"gx:confidentialComputingTechnology,omitempty"`
}

// ServiceOffering represents a digital service available for order
type ServiceOffering struct {
	GaiaXEntity
	// A resolvable link of resources related to an entity and that can exist independently of it
	AggregationOfResources []ResourceInterface `json:"gx:aggregationOfResources,omitempty"`
	// A resolvable link to Gaia-X Credential of the participant providing the service
	ProvidedBy LegalPerson `json:"gx:providedBy,omitempty"`
	// List of service offerings this service depends on
	DependsOn []ServiceOffering `json:"gx:dependsOn,omitempty"`
	// One or more Terms and Conditions applying to that service
	ServiceOfferingTermsAndConditions []TermsAndConditions `json:"gx:serviceOfferingTermsAndConditions"`
	// One or more policies expressed using a DSL
	ServicePolicy []AccessUsagePolicy `json:"gx:servicePolicy,omitempty"`
	// One or more data protection regimes applying to the service offering
	DataProtectionRegime []string `json:"gx:dataProtectionRegime,omitempty"`
	// One or more methods to export data out of the service
	DataAccountExport []DataAccountExport `json:"gx:dataAccountExport"`
	// Keywords that describe / tag the service
	Keyword []string `json:"gx:keyword,omitempty"`
	// Provision type of the service
	ProvisionType any `json:"gx:provisionType,omitempty"`
	// Endpoint through which the Service Offering can be accessed
	Endpoint *Endpoint `json:"gx:endpoint,omitempty"`
	// List of Resource references where service is hosted
	HostedOn []ResourceInterface `json:"gx:hostedOn,omitempty"`
	// Plain text describing the service scope
	ServiceScope string `json:"gx:serviceScope,omitempty"`
	// A list of legal documents in relation to the service or the customer
	LegalDocuments []LegalDocument `json:"gx:legalDocuments,omitempty"`
	// A list of sub-contractors processing customer data
	SubContractors []SubContractor `json:"gx:subContractors,omitempty"`
	// One or more customer instructions describing the Customer instructions regarding any data therein
	CustomerInstructions []CustomerInstructions `json:"gx:customerInstructions,omitempty"`
	// One or more data portability documents describing the data portability measures
	DataPortability []DataPortability `json:"gx:dataPortability,omitempty"`
	// One or more data transfer documents describing if and to which extent Customer data transfers will happen
	PossiblePersonalDataTransfers []DataTransfer `json:"gx:possiblePersonalDataTransfers,omitempty"`
	// One or more technical and organizational measures
	RequiredMeasures []Measure `json:"gx:requiredMeasures,omitempty"`
	// One or more cryptographic security standards protecting authenticity or integrity of the data
	CryptographicSecurityStandards []string `json:"gx:cryptographicSecurityStandards,omitempty"`
	// The contact information where the customer can contact the provider of this service
	ProviderContactInformation ContactInformation `json:"gx:providerContactInformation,omitempty,omitzero"`
}

func (so *ServiceOffering) AddResourceURI(uri string) {
	r := Resource{}
	r.ID = uri
	so.AggregationOfResources = append(so.AggregationOfResources, r)
}

func (so *ServiceOffering) AddCustomerInstructionsURI(uri string) {
	r := CustomerInstructions{}
	r.ID = uri
	so.CustomerInstructions = append(so.CustomerInstructions, r)
}

func (so *ServiceOffering) AddDataAccountExportURI(uri string) {
	r := DataAccountExport{}
	r.ID = uri
	so.DataAccountExport = append(so.DataAccountExport, r)
}

func (so *ServiceOffering) AddDataPortabilityURI(uri string) {
	r := DataPortability{}
	r.ID = uri
	so.DataPortability = append(so.DataPortability, r)
}

func (so *ServiceOffering) AddLegalDocumentURI(uri string) {
	r := LegalDocument{}
	r.ID = uri
	so.LegalDocuments = append(so.LegalDocuments, r)
}

func (so *ServiceOffering) AddRequiredMeasuresURI(uri string) {
	r := Measure{}
	r.ID = uri
	so.RequiredMeasures = append(so.RequiredMeasures, r)
}

func (so *ServiceOffering) AddServiceOfferingTermsAndConditionsURI(uri string) {
	r := TermsAndConditions{}
	r.ID = uri
	so.ServiceOfferingTermsAndConditions = append(so.ServiceOfferingTermsAndConditions, r)
}

func (so *ServiceOffering) AddSubContractorURI(uri string) {
	r := SubContractor{}
	r.ID = uri
	so.SubContractors = append(so.SubContractors, r)
}

// InfrastructureServiceOffering represents computational, storage and/or network capabilities
type InfrastructureServiceOffering struct {
	ServiceOffering
}

// ComputeServiceOffering represents a service offering computational capabilities
type ComputeServiceOffering struct {
	InfrastructureServiceOffering
	// How compute resources of different tenants are separated
	TenantSeparation string `json:"gx:tenantSeparation,omitempty"`
}

// VirtualMachineServiceOffering represents VM computational capabilities
type VirtualMachineServiceOffering struct {
	ComputeServiceOffering
	// Compute Service Code Artifacts
	CodeArtifact []VM_Image `json:"gx:codeArtifact"`
	// Set of technical requirements or conditions to instantiate this service offering
	InstantiationReq []ServerFlavor `json:"gx:instantiationReq"`
}

// ContainerServiceOffering represents container capabilities
type ContainerServiceOffering struct {
	ComputeServiceOffering
	// All possible provided container images for this service offering
	CodeArtifact []ContainerImage `json:"gx:codeArtifact"`
	// All possible provided container resource limits for this service offering
	InstantiationReq []ContainerResourceLimits `json:"gx:instantiationReq"`
}

// BareMetalServiceOffering represents bare metal computational capabilities
type BareMetalServiceOffering struct {
	ComputeServiceOffering
	// Set of available bare metal server images for this service offering
	CodeArtifact []PXE_Image `json:"gx:codeArtifact"`
	// Set of bare metal server flavors available for this service offering
	InstantiationReq []ServerFlavor `json:"gx:instantiationReq"`
}

// TermsAndConditions represents terms applying to a service offering
type TermsAndConditions struct {
	vc.CredentialSubjectShape
	// A resolvable link to the terms & conditions document
	URL vc.URL `json:"gx:url,omitempty,omitzero"`
	// SHA-256 hash of the document
	Hash string `json:"gx:hash,omitempty,omitzero"`
}

// DataAccountExport represents methods to export data from a service
type DataAccountExport struct {
	vc.CredentialSubjectShape
	// The mean to request data retrieval
	RequestType string `json:"gx:requestType,omitempty,omitzero"`
	// Type of data support: digital, physical
	AccessType string `json:"gx:accessType,omitempty,omitzero"`
	// Type of Media Types (formerly known as MIME types) as defined by the IANA
	FormatType string `json:"gx:formatType,omitempty,omitzero"`
}

// Endpoint represents a means to access and interact with a service or resource
type Endpoint struct {
	// The URL of the endpoint where it can be accessed
	EndpointURL vc.URL `json:"gx:endpointURL"`
	// Provides information about applied standards
	StandardConformity []StandardConformity `json:"gx:standardConformity"`
	// The formal description (e.g. openAPI Description) of the endpoint
	FormalDescription string `json:"gx:formalDescription,omitempty"`
}

// StandardConformity provides information about applied standards
type StandardConformity struct {
	// Name of the standard
	Title string `json:"dct:title"`
	// Provides a link to schemas or details about applied standards
	StandardReference vc.URL `json:"gx:standardReference"`
	// Publisher of the standard
	Publisher string `json:"gx:publisher,omitempty"`
}

// ContactInformation contains contact details for an entity
type ContactInformation struct {
	vc.CredentialSubjectShape
	// Postal address of the contact
	PostalAddress Address `json:"gx:postalAddress,omitempty,omitzero"`
	// Email address of the contact
	Email string `json:"gx:email,omitempty,omitzero"`
	// Phone number of the contact
	PhoneNumber string `json:"gx:phoneNumber,omitempty,omitzero"`
	// URI for the contact
	URI string `json:"gx:uri,omitempty,omitzero"`
	URL vc.URL `json:"gx:url,omitempty,omitzero"`
}

// CustomerInstructions defines how customers can instruct providers regarding data processing
type CustomerInstructions struct {
	vc.CredentialSubjectShape
	// Required: Terms and conditions to provide instructions for processing the data
	Terms []LegalDocument `json:"gx:terms,omitzero"`
	// Required: Means used to accomplish a task
	Means []LegalDocument `json:"gx:means,omitzero"`
}

// LegalDocument represents a document with legal significance
type LegalDocument struct {
	vc.CredentialSubjectShape
	// Required: Resolvable link to a resource
	URL vc.URL `json:"gx:url,omitzero,omitempty"`
	// Multipurpose Internet Mail Extensions indicating the format of a resource
	MimeTypes []string `json:"gx:mimeTypes,omitempty"`
	// Countries under whose laws the resource is governed
	GoverningLawCountries []string `json:"gx:governingLawCountries,omitempty"`
	// Legal persons involved in a task, organization or other concept
	InvolvedParties []LegalPerson `json:"gx:involvedParties,omitempty"`
}

// DataPortability represents the data portability measures for a service
type DataPortability struct {
	vc.CredentialSubjectShape
	// Resource of the service offering concerned by data portability
	Resource string `json:"gx:resource,omitzero"`
	// Allows to provide a specific provider contact point for data portability
	ContactInformation *ContactInformation `json:"gx:contactInformation,omitempty"`
	// Required: Means used to transfer the customer's stored data to another provider
	Means []string `json:"gx:means,omitzero"`
	// Documentations explaining how data portability can be done
	Documentations []vc.URL `json:"gx:documentations,omitzero"`
	// Required: Legal document describing the data portability agreement
	LegalDocument LegalDocument `json:"gx:legalDocument,omitzero"`
	// Required: Methods used to delete the customer's data
	DeletionMethods []string `json:"gx:deletionMethods,omitzero"`
	// Required: Timeframe within which the customer's data will be deleted
	DeletionTimeframe string `json:"gx:deletionTimeframe,omitzero"`
	// Required: Technical formats for importation or exportation processes
	Formats []string `json:"gx:formats,omitzero"`
	// Required: Link to the service's pricing page
	Pricing vc.URL `json:"gx:pricing,omitzero"`
}

// DataTransfer represents data transfer details including reasons and scope
type DataTransfer struct {
	// Legal basis for which the transfer might occur
	LegalBasis string `json:"gx:legalBasis"`
	// Reason for which the transfer might occur
	Reason string `json:"gx:reason"`
	// Perimeter of data that will be transferred
	Scope string `json:"gx:scope"`
}

// SubProcessorDataTransfer specifies data transfer to a sub-processor
type SubProcessorDataTransfer struct {
	DataTransfer
	// Sub-processor to which the data can be transferred
	SubProcessor LegalPerson `json:"gx:subProcessor"`
	// Management means of the sub-processor
	SubProcessorManagement LegalDocument `json:"gx:subProcessorManagement"`
}

// ThirdCountryDataTransfer specifies data transfer to a third country
type ThirdCountryDataTransfer struct {
	DataTransfer
	// Country to which the data can be transferred
	Country string `json:"gx:country"`
	// Mechanism used to secure the data transfer
	SecuringMechanism []string `json:"gx:securingMechanism"`
}

// Measure defines a specific security or privacy measure taken
type Measure struct {
	vc.CredentialSubjectShape
	// Required Description of the measure, unkown why httpsschema namespace is used
	Description string `json:"httpsschema:description,omitzero"`
	// Required Legal documents associated with the measure
	LegalDocuments []LegalDocument `json:"gx:legalDocuments,omitzero,omitempty"`
}

// SubContractor represents a subcontractor with specific legal and communication attributes
type SubContractor struct {
	vc.CredentialSubjectShape
	// The jurisdiction under which the subcontractor operates
	ApplicableJurisdiction string `json:"gx:applicableJurisdiction,omitempty,omitzero"`
	// The legal name of the subcontractor
	LegalName string `json:"gx:legalName,omitempty,omitzero"`
	// Required: The method of communication with the subcontractor
	CommunicationMethods []LegalDocument `json:"gx:communicationMethods,omitzero,omitempty"`
	// Required: Documents providing additional information about the subcontractor
	InformationDocuments []LegalDocument `json:"gx:informationDocuments,omitzero,omitempty"`
}

// AccessUsagePolicy represents an access or usage policy expressed using a DSL
type AccessUsagePolicy struct {
	GaiaXEntity
	// The language in which the policy is expressed
	PolicyLanguage string `json:"gx:policyLanguage,omitempty"`
	// A link to the actual policy or the content of the policy itself
	PolicyDocument string `json:"gx:policyDocument,omitempty"`
}

// EnergyUsageEfficiency represents the efficiency of energy usage in a resource
type EnergyUsageEfficiency struct {
	// Legal documents containing certifications
	Certifications []LegalDocument `json:"gx:certifications,omitempty"`
	// The effectiveness of power usage, represented as a float
	PowerUsageEffectiveness float64 `json:"gx:powerUsageEffectiveness"`
}

// WaterUsageEffectiveness represents the effectiveness of water usage in a resource
type WaterUsageEffectiveness struct {
	// Legal documents certifying the water usage effectiveness
	Certifications []LegalDocument `json:"gx:certifications,omitempty"`
	// The effectiveness of water usage, represented as a float
	WaterUsageEffectiveness float64 `json:"gx:waterUsageEffectiveness"`
}

// EnergyMix details the composition of energy sources
type EnergyMix struct {
	// Date for which this energy mix has been attained
	Date time.Time `json:"gx:date"`
	// Percentage of renewable energy in the energy mix
	RenewableEnergy float64 `json:"gx:renewableEnergy"`
	// Percentage of hourly carbon-free energy in the energy mix
	HourlyCarbonFreeEnergy float64 `json:"gx:hourlyCarbonFreeEnergy"`
}

// QoSMetric represents a quality of service metric with a guaranteed performance level
type QoSMetric struct {
	// Metric used to measure an indicator
	Metric interface{} `json:"gx:metric"`
	// Minimum percentage of time where a performance-level is guaranteed to be met
	Guaranteed *FloatPercentage `json:"gx:guaranteed,omitempty"`
}

// BandWidth represents a bandwidth specification with a guaranteed level
type BandWidth struct {
	QoSMetric
	// The metric must be a DataRate type
}

// RoundTripTime represents the round trip time specification with a guaranteed level
type RoundTripTime struct {
	QoSMetric
	// The metric must be a Time type
}

// Availability represents service availability with a guaranteed level
type Availability struct {
	QoSMetric
	// The metric must be a Time type
}

// PacketLoss represents packet loss specification with a guaranteed level
type PacketLoss struct {
	QoSMetric
	// The metric must be a FloatPercentage type
}

// Jitter represents jitter specification with a guaranteed level
type Jitter struct {
	QoSMetric
	// The metric must be a Time type
}

// Latency represents latency specification with a guaranteed level
type Latency struct {
	QoSMetric
	// The metric must be a Time type
}

// TargetPercentile represents target percentile specification
type TargetPercentile struct {
	QoSMetric
	// The metric must be a FloatPercentage type
}

// Throughput represents throughput specification with a guaranteed level
type Throughput struct {
	QoSMetric
	// The metric must be a DataRate type
}

// IOPS represents I/O operations per second with a guaranteed level
type IOPS struct {
	QoSMetric
	// The metric must be a DataRate type
}

// QoS represents a set of quality of service metrics
type QoS struct {
	// Metric for throughput
	Throughput *Throughput `json:"gx:throughput,omitempty"`
	// Metric for Input/Output operations per second
	Iops *IOPS `json:"gx:iops,omitempty"`
	// Contractual bandwidth defined in the service level agreement (SLA)
	BandWidth *BandWidth `json:"gx:bandWidth,omitempty"`
	// Contractual roundTrip time defined in the SLA
	RoundTripTime *RoundTripTime `json:"gx:roundTripTime,omitempty"`
	// Contractual availability of connection defined in the SLA agreement
	Availability *Availability `json:"gx:availability,omitempty"`
	// Contractual packet loss of connection defined in the SLA agreement
	PacketLoss *PacketLoss `json:"gx:packetLoss,omitempty"`
	// Contractual jitter defined in the SLA
	Jitter *Jitter `json:"gx:jitter,omitempty"`
	// Contractual latency defined in the SLA
	Latency *Latency `json:"gx:latency,omitempty"`
	// Contractual percentile in the SLA
	TargetPercentile *TargetPercentile `json:"gx:targetPercentile,omitempty"`
}

// ConnectivityConfiguration encapsulates connectivity parameters
type ConnectivityConfiguration struct {
	InstantiationRequirement
	// InterconnectionPointIdentifier reference of the source service access point
	SourceIdentifierA string `json:"gx:sourceIdentifierA"`
	// InterconnectionPointIdentifier reference of the destination service access point
	DestinationIdentifierZ string `json:"gx:destinationIdentifierZ"`
}

// ConnectivityServiceOffering represents a connectivity infrastructure service
type ConnectivityServiceOffering struct {
	InfrastructureServiceOffering
	// All possible provided connectivity parameters for this network connectivity service offering
	ConnectivityConfiguration []ConnectivityConfiguration `json:"gx:connectivityConfiguration"`
	// Contractual performance values defined in the SLA
	ConnectivityQoS *QoS `json:"gx:connectivityQoS,omitempty"`
}

// NetworkConnectivityServiceOffering represents network connectivity capabilities
type NetworkConnectivityServiceOffering struct {
	ConnectivityServiceOffering
	// Type of Service Offering
	ServiceType string `json:"gx:serviceType,omitempty"`
	// Defines how public IP address are provided
	PublicIpAddressProvisioning string `json:"gx:publicIpAddressProvisioning,omitempty"`
	// Version of IP address supported
	IpVersion string `json:"gx:ipVersion,omitempty"`
	// How compute resources of different tenants are separated
	TenantSeparation string `json:"gx:tenantSeparation,omitempty"`
}

// VLANConfiguration represents VLAN configuration settings
type VLANConfiguration struct {
	// The chosen types of vlan types
	VlanType string `json:"gx:vlanType"`
	// Vlan Tag ID that range between 1 and 4094
	VlanTag int `json:"gx:vlanTag"`
	// The ether type of the vlan in hexadecimal notation
	VlanEtherType string `json:"gx:vlanEtherType,omitempty"`
}

// InterconnectionServiceOffering represents interconnection capabilities
type InterconnectionServiceOffering struct {
	NetworkConnectivityServiceOffering
	// Autonomous system (AS) number (ASN) of the side A
	ConnectedNetworkA []int `json:"gx:connectedNetworkA,omitempty"`
	// Autonomous system (AS) number (ASN) of the side Z
	ConnectedNetworkZ []int `json:"gx:connectedNetworkZ,omitempty"`
	// CIDR Provider Identifier of network on the side A
	PrefixSetA []string `json:"gx:prefixSetA,omitempty"`
	// CIDR Provider Identifier of network on the side Z
	PrefixSetZ []string `json:"gx:prefixSetZ,omitempty"`
	// VLAN configuration
	VlanConfiguration *VLANConfiguration `json:"gx:vlanConfiguration,omitempty"`
	// The supported types of connection
	ConnectionType []string `json:"gx:connectionType,omitempty"`
	// A type of interface whether it's physical or virtual
	InterfaceType string `json:"gx:interfaceType,omitempty"`
}

// LinkConnectivityServiceOffering represents link connectivity capabilities
type LinkConnectivityServiceOffering struct {
	ConnectivityServiceOffering
	// Link protocol type
	ProtocolType string `json:"gx:protocolType"`
	// VLAN configuration
	VlanConfiguration *VLANConfiguration `json:"gx:vlanConfiguration,omitempty"`
}

// PhysicalConnectivityServiceOffering represents physical connectivity capabilities
type PhysicalConnectivityServiceOffering struct {
	ConnectivityServiceOffering
	// The type of physical circuit
	CircuitType string `json:"gx:circuitType"`
	// A type of physical interface
	InterfaceType string `json:"gx:interfaceType"`
}

// StorageConfiguration represents the configurable attributes at service instantiation
type StorageConfiguration struct {
	InstantiationRequirement
	// Available compression features
	StorageCompression []string `json:"gx:storageCompression,omitempty"`
	// Deduplication features available for the storage service
	StorageDeduplication []string `json:"gx:storageDeduplication,omitempty"`
	// Available encryption features
	StorageEncryption []Encryption `json:"gx:storageEncryption,omitempty"`
	// Underlying data protection mechanism
	StorageRedundancyMechanism []string `json:"gx:storageRedundancyMechanism,omitempty"`
	// Available data protection features
	StorageProtection []string `json:"gx:storageProtection,omitempty"`
	// Available QoS class for storage service
	StorageQoS []QoS `json:"gx:storageQoS,omitempty"`
	// Available block size to be used
	BlockSize []MemorySize `json:"gx:blockSize,omitempty"`
}

// FileStorageConfiguration extends StorageConfiguration for file storage
type FileStorageConfiguration struct {
	StorageConfiguration
	// Filesystem Type for storage partition
	FileSystemType []string `json:"gx:fileSystemType,omitempty"`
	// Underlying higher level access protocol
	HighLevelAccessProtocol []string `json:"gx:highLevelAccessProtocol,omitempty"`
}

// BlockStorageConfiguration extends StorageConfiguration for block storage
type BlockStorageConfiguration struct {
	StorageConfiguration
	// Underlying storage technology type to be used
	BlockStorageTechnology []string `json:"gx:blockStorageTechnology,omitempty"`
	// Underlying low level access protocol for the storage service
	LowLevelBlockAccessProtocol []string `json:"gx:lowLevelBlockAccessProtocol,omitempty"`
}

// StorageServiceOffering represents storage capabilities
type StorageServiceOffering struct {
	InfrastructureServiceOffering
	// Minimum Capacity (expressed as value + unit) supported by the service
	MinimumSize *MemorySize `json:"gx:minimumSize,omitempty"`
	// Maximum Capacity (expressed as value + unit) supported by the service
	MaximumSize *MemorySize `json:"gx:maximumSize,omitempty"`
	// Attributes that are configurable at service instantiation
	StorageConfiguration *StorageConfiguration `json:"gx:storageConfiguration"`
	// Lifetime of data before it is moved externally, archived or deleted
	LifetimeManagement int `json:"gx:lifetimeManagement,omitempty"`
	// Whether versioning is available on this storage service
	Versioning bool `json:"gx:versioning,omitempty"`
	// Consistency model provided
	StorageConsistency string `json:"gx:storageConsistency,omitempty"`
	// Capability to compose logical data views
	DataViews bool `json:"gx:dataViews,omitempty"`
	// Capability for multiple views
	MultipleViews bool `json:"gx:multipleViews,omitempty"`
}

// FileStorageServiceOffering represents file storage capabilities
type FileStorageServiceOffering struct {
	StorageServiceOffering
	// Whether I/O conforms to the POSIX standard
	AccessSemantics bool `json:"gx:accessSemantics,omitempty"`
	// Supported access attributes
	AccessAttributes []string `json:"gx:accessAttributes,omitempty"`
}

// BlockStorageServiceOffering represents block storage capabilities
type BlockStorageServiceOffering struct {
	StorageServiceOffering
	// StorageConfiguration must be of type BlockStorageConfiguration
}

// ObjectStorageServiceOffering represents object storage capabilities
type ObjectStorageServiceOffering struct {
	StorageServiceOffering
	// Supported access attributes
	AccessAttributes []string `json:"gx:accessAttributes,omitempty"`
	// Maximum size for objects supported by the service
	MaximumObjectSize *MemorySize `json:"gx:maximumObjectSize,omitempty"`
	// Compatibility for third party object storage APIs
	ObjectAPICompatibility []string `json:"gx:objectAPICompatibility,omitempty"`
}

// DataProtectionPolicy provides data protection features
type DataProtectionPolicy struct {
	// Frequency at which data are captured/protected
	ProtectionFrequency string `json:"gx:protectionFrequency"`
	// How long captured/protected data are kept available
	ProtectionRetention *RetentionDuration `json:"gx:protectionRetention"`
	// Method used to protect data
	ProtectionMethod string `json:"gx:protectionMethod,omitempty"`
}

// BackupPolicy describes data protection features based on Backup
type BackupPolicy struct {
	DataProtectionPolicy
	// Where are located data backups
	BackupLocation []ResourceInterface `json:"gx:backupLocation"`
	// Backups replication policy, if any
	BackupReplication []ReplicationPolicy `json:"gx:backupReplication,omitempty"`
}

// SnapshotPolicy describes data protection features based on Snapshot
type SnapshotPolicy struct {
	DataProtectionPolicy
	// Snapshots replication policy, if any
	SnapshotReplication []ReplicationPolicy `json:"gx:snapshotReplication,omitempty"`
}

// ReplicationPolicy describes data protection features based on Replication
type ReplicationPolicy struct {
	DataProtectionPolicy
	// Whether replication is performed in synchronous mode
	SynchronousReplication bool `json:"gx:synchronousReplication,omitempty"`
	// Type of consistency supported
	ConsistencyType string `json:"gx:consistencyType,omitempty"`
	// How many independent copies are made
	ReplicaNumber []int `json:"gx:replicaNumber,omitempty"`
	// Scope of geo-replication
	GeoReplication []string `json:"gx:geoReplication,omitempty"`
}

// ComputeFunctionConfiguration represents InstantiationRequirements for compute functions
type ComputeFunctionConfiguration struct {
	InstantiationRequirement
	// Quotas available for compute functions
	ComputeFunctionQuotas []ComputeFunctionQuotas `json:"gx:computeFunctionQuotas,omitempty"`
	// Library of compute function templates available
	ComputeFunctionLibrary []ComputeFunctionTemplate `json:"gx:computeFunctionLibrary,omitempty"`
	// Available runtime for executing function
	ComputeFunctionRuntime []ComputeFunctionRuntime `json:"gx:computeFunctionRuntime"`
	// SDKs provided to ease function development
	ComputeFunctionSDK []ComputeFunctionRuntime `json:"gx:computeFunctionSDK,omitempty"`
	// Available trigger for starting function execution
	ComputeFunctionTrigger []ComputeFunctionTrigger `json:"gx:computeFunctionTrigger,omitempty"`
	// Supported methods for importing/deploying compute function code
	ComputeFunctionDeploymentMethod []string `json:"gx:computeFunctionDeploymentMethod,omitempty"`
	// Details with respect to confidential computing requirements
	ConfidentialComputingTechnology *ConfidentialComputing `json:"gx:confidentialComputingTechnology,omitempty"`
}

// ComputeFunctionQuotas describes quotas for compute functions
type ComputeFunctionQuotas struct {
	// Maximum number of functions that can be created
	FunctionMaximumNumber int `json:"gx:functionMaximumNumber,omitempty"`
	// Storage limit for deployed functions
	FunctionStorageLimit *MemorySize `json:"gx:functionStorageLimit,omitempty"`
	// Maximum execution time for a function
	FunctionTimeLimit *Time `json:"gx:functionTimeLimit,omitempty"`
	// Maximum amount of memory usable by a function
	FunctionMemoryLimit *MemorySize `json:"gx:functionMemoryLimit,omitempty"`
	// Maximum size of a deployed function
	FunctionSizeLimit *MemorySize `json:"gx:functionSizeLimit,omitempty"`
	// Maximum number of concurrent execution of a function
	FunctionConcurrencyLimit int `json:"gx:functionConcurrencyLimit,omitempty"`
	// Maximum size for incoming request for a function
	FunctionRequestSizeLimit *MemorySize `json:"gx:functionRequestSizeLimit,omitempty"`
	// Maximum size for a function response
	FunctionResponseSizeLimit *MemorySize `json:"gx:functionResponseSizeLimit,omitempty"`
}

// ComputeFunctionRuntime describes function runtimes
type ComputeFunctionRuntime struct {
	// Language for writing compute function
	SupportedLanguage string `json:"gx:supportedLanguage"`
	// Supported version for Runtime language
	SupportedVersion []string `json:"gx:supportedVersion"`
}

// ComputeFunctionTrigger describes Compute Function Triggers
type ComputeFunctionTrigger struct {
	// Service providing the events usable to trigger execution of a ComputeFunction
	TriggeringService ServiceOffering `json:"gx:triggeringService,omitempty"`
	// Events usable to trigger execution of a ComputeFunction
	TriggeringEvent []string `json:"gx:triggeringEvent,omitempty"`
}

// ComputeFunctionTemplate describes a template of compute function
type ComputeFunctionTemplate struct {
	CodeArtifact
	// Name of this function template
	ComputeFunctionName string `json:"gx:computeFunctionName"`
	// Description of what the function template does
	ComputeFunctionDescription string `json:"gx:computeFunctionDescription"`
	// Runtime(s) available for this function template
	ComputeFunctionTemplateRuntime []ComputeFunctionRuntime `json:"gx:computeFunctionTemplateRuntime"`
}

// ComputeFunctionServiceOffering represents compute functions capabilities
type ComputeFunctionServiceOffering struct {
	ComputeServiceOffering
	// Attributes configurable at service instantiation
	ComputeFunctionConfiguration *ComputeFunctionConfiguration `json:"gx:computeFunctionConfiguration"`
	// Indicates whether the service includes debugging tools
	ComputeFunctionDebugTools bool `json:"gx:computeFunctionDebugTools,omitempty"`
	// Indicates whether the service includes a code editor
	ComputeFunctionEditor bool `json:"gx:computeFunctionEditor,omitempty"`
	// Indicates whether the service allows defining resource quotas for functions
	ComputeFunctionAllowQuota bool `json:"gx:computeFunctionAllowQuota,omitempty"`
	// Indicates whether the service allows defining timeouts for functions
	ComputeFunctionAllowTimeout bool `json:"gx:computeFunctionAllowTimeout,omitempty"`
	// Indicates whether the service allows code versioning for functions
	ComputeFunctionAllowVersioning bool `json:"gx:computeFunctionAllowVersioning,omitempty"`
	// Indicates whether the service supports auto-scaling of functions
	ComputeFunctionAllowAutoScaling bool `json:"gx:computeFunctionAllowAutoScaling,omitempty"`
	// Indicates whether the service supports mounting and using external file systems
	ComputeFunctionAllowFSMount bool `json:"gx:computeFunctionAllowFSMount,omitempty"`
}

// DataResource represents a dataset exposed through a service instance
type DataResource struct {
	VirtualResource
	// Designates the producer of a concept
	ProducedBy LegalPerson `json:"gx:producedBy"`
	// required: A resolvable link to the data exchange component that exposes the Data Product
	ExposedThrough any `json:"gx:exposedThrough"` // todo gx:DataExchangeComponent
	// Date time in ISO 8601 format after which data is obsolete and shall be deleted
	ObsoleteDateTime any `json:"gx:obsoleteDateTime,omitzero"` //todo change type similar to xsd:string not with xsd:dateTime
	// Date time in ISO 8601 format after which data is expired and shall be deleted
	ExpirationDateTime any `json:"gx:expirationDateTime,omitzero"` //todo change type similar to xsd:string not with xsd:dateTime
	// Boolean for Personal Identifier Information
	ContainsPII bool `json:"gx:containsPII"`
	// Data controller Participant as defined in GDPR
	DataController []Participant `json:"gx:dataController,omitempty"`
	// List of consents covering the processing activities from the data subjects
	Consent []Consent `json:"gx:consent,omitempty"`
}

// Consent contains information on the legitimate processing of personal information
type Consent struct {
	// Legal basis for processing PII
	LegalBasis string `json:"gx:legalBasis"`
	// ContactPoint of the Data Protection Officer
	DataProtectionContactPoint string `json:"gx:dataProtectionContactPoint,omitempty"`
	// Purposes of the processing
	Purpose []string `json:"gx:purpose,omitempty"`
	// ContactPoint to formulate a withdrawal consent request
	ConsentWithdrawalContactPoint string `json:"gx:consentWithdrawalContactPoint,omitempty"`
}

// Datacenter is an aggregation of availability zones
type Datacenter struct {
	PhysicalResource
	// References those availability zones out of which a datacenter is aggregated
	// AggregationOfResources field is inherited from Resource
}

// AvailabilityZone is an aggregation of resources in a non-redundant setup
type AvailabilityZone struct {
	Resource
	// The physical address associated with the availability zone
	Address Address `json:"gx:address,omitempty"`
}

// Region is an aggregation of datacenters
type Region struct {
	Resource
	// The physical address associated with the region
	Address Address `json:"gx:address,omitempty"`
	// References those datacenters out of which a region is aggregated
	// AggregationOfResources field is inherited from Resource
}

// InterconnectionPointIdentifier uniquely identifies where resources can interconnect
type InterconnectionPointIdentifier struct {
	vc.CredentialSubjectShape
	// Type of the interconnection point identifier
	IpiType string `json:"gx:ipiType,omitempty"`
	// The Provider of the IPI
	IpiProvider string `json:"gx:ipiProvider,omitempty"`
	// Type or Provider Specific Parameters, separated by colons
	SpecificParameters string `json:"gx:specificParameters,omitempty"`
	// Required: Unique label identifying structure of an IPI, e.g. IP-Address
	CompleteIPI string `json:"gx:completeIPI,omitempty"`
	// Details specific situation within the datacenter where the service can be accessed
	DatacenterAllocation *DatacenterAllocation `json:"gx:datacenterAllocation,omitempty"`
	// The mac address required for L2 connectivity setup
	MacAddress string `json:"gx:macAddress,omitempty"`
	// The IP address required for L3 connectivity setup
	IpAddress string `json:"gx:ipAddress,omitempty"`
}

// DatacenterAllocation details specific location within a datacenter
type DatacenterAllocation struct {
	// Datacenter where the service can be accessed
	RefersTo Datacenter `json:"gx:refersTo"`
	// The floor number of the datacenter where the service can be accessed
	Floor string `json:"gx:floor,omitempty"`
	// The Id of the datacenter rack number where the service can be accessed
	RackNumber string `json:"gx:rackNumber,omitempty"`
	// The Id of the datacenter patch panel where the service can be accessed
	PatchPanel string `json:"gx:patchPanel,omitempty"`
	// The port number on the patch panel where the service can be accessed
	PortNumber int `json:"gx:portNumber,omitempty"`
}

// PointOfPresence represents a point of connection between communicating entities
type PointOfPresence struct {
	PhysicalResource
	// Required: Legal persons interconnecting their networks via this point of presence, unsure which one works sh does include participant, GXDCH validates against interconnected
	Participants               []LegalPerson `json:"gx:participants,omitempty,omitzero"`               // ? gx:interconnectedParticipants
	InterconnectedParticipants []LegalPerson `json:"gx:interconnectedParticipants,omitempty,omitzero"` // ? gx:interconnectedParticipants
	// Required: Definition of the location where resources can interconnect
	InterconnectionPointIdentifier InterconnectionPointIdentifier `json:"gx:interconnectionPointIdentifier,omitempty,omitzero"`
}

// PhysicalInterconnectionPointIdentifier represents a physical interconnection point
type PhysicalInterconnectionPointIdentifier struct {
	PointOfPresence
}

// VirtualInterconnectionPointIdentifier represents a virtual interconnection point
type VirtualInterconnectionPointIdentifier struct {
	VirtualResource
	// Legal persons participating within a concept
	Participants []LegalPerson `json:"gx:participants"`
	// Definition of the location where resources can interconnect
	InterconnectionPointIdentifier InterconnectionPointIdentifier `json:"gx:interconnectionPointIdentifier"`
}

// InternetExchangePoint is a physical infrastructure allowing participants to interconnect networks
type InternetExchangePoint struct {
	PhysicalInterconnectionPointIdentifier
}

// InternetServiceProvider is an organization providing internet access and related services
type InternetServiceProvider struct {
	LegalPerson
}

// Issuer is an entity that can issue W3C Verifiable Credentials and Verifiable Presentations
type Issuer struct {
	vc.CredentialSubjectShape
	// Gaia-X terms and conditions this issuer agreed with
	GaiaxTermsAndConditions string `json:"gx:gaiaxTermsAndConditions,omitempty,omitzero"`
}

// LabelCredential represents a Gaia-X conformity label level
type LabelCredential struct {
	// Abbreviated conformity level of the label credential (SC, L1, L2, ...)
	LabelLevel string `json:"gx:labelLevel"`
	// Gaia-X compliance engine version that delivered a label credential
	EngineVersion string `json:"gx:engineVersion"`
	// Gaia-X compliance document version from which the validated criteria originate
	RulesVersion string `json:"gx:rulesVersion"`
	// Gaia-X compliance document version from which the validated criteria originate
	ValidatedCriteria []string `json:"gx:validatedCriteria"`
	// Credentials validated by the compliance engine and linked to a label credential
	CompliantCredentials []CompliantCredential `json:"gx:compliantCredentials"`
}

// CompliantCredential represents a snapshot of a credential deemed compliant
type CompliantCredential struct {
	// Type of the compliant credential
	CredentialType string `json:"gx:credentialType"`
	// Subresource Integrity hash of the verifiable credential
	DigestSRI string `json:"cred:digestSRI"`
}

// DataExchangeComponent represents a service/resource used to make a data resource available
type DataExchangeComponent struct{}

// Policy represents an ODRL policy
type Policy struct {
	// Unique identifier for policies
	UID string `json:"odrl:uid,omitempty"`
	// Profile information for the policy
	Profile string `json:"odrl:profile,omitempty"`
	// Indicates inheritance from another policy
	InheritFrom string `json:"odrl:inheritFrom,omitempty"`
	// Defines a permission
	Permission []Rule `json:"odrl:permission,omitempty"`
	// Defines a prohibition
	Prohibition []Rule `json:"odrl:prohibition,omitempty"`
	// Defines an obligation
	Obligation []Rule `json:"odrl:obligation,omitempty"`
}

// Agreement represents an ODRL agreement policy
type Agreement struct {
	Policy
	// Party assigned a responsibility
	Assignee interface{} `json:"odrl:assignee"`
	// Party assigning a responsibility
	Assigner interface{} `json:"odrl:assigner"`
}

// Offer represents an ODRL offer policy
type Offer struct {
	Policy
	// Party assigning a responsibility
	Assigner interface{} `json:"odrl:assigner"`
}

// Set represents an ODRL policy set
type Set struct {
	Policy
}

// Rule represents an ODRL rule
type Rule struct {
	// Describes relationships between rules
	Relation string `json:"odrl:relation,omitempty"`
	// Function description in rules
	Function string `json:"odrl:function,omitempty"`
	// Failure conditions in rules
	Failure string `json:"odrl:failure,omitempty"`
	// Action to perform
	Action string `json:"odrl:action"`
	// Party assigned a responsibility
	Assignee interface{} `json:"odrl:assignee,omitempty"`
	// Party assigning a responsibility
	Assigner interface{} `json:"odrl:assigner,omitempty"`
	// Rule constraint
	Constraint []Constraint `json:"odrl:constraint,omitempty"`
	// Logical constraint
	LogicalConstraint []LogicalConstraint `json:"odrl:logicalConstraint,omitempty"`
	// Defines a duty
	Duty []Rule `json:"odrl:duty,omitempty"`
}

// ConflictTerm represents ODRL conflict handling terms
type ConflictTerm struct {
	// Conflict strategy
	Conflict string `json:"odrl:conflict,omitempty"`
	// Permission in conflict
	Perm string `json:"odrl:perm,omitempty"`
	// Prohibition in conflict
	Prohibit string `json:"odrl:prohibit,omitempty"`
	// Invalid state
	Invalid string `json:"odrl:invalid,omitempty"`
}

// Asset represents an ODRL Asset
type Asset struct {
	// A collection of assets
	AssetCollection string `json:"odrl:AssetCollection,omitempty"`
	// Unique identifier for the asset
	UID string `json:"odrl:uid,omitempty"`
}

// Party represents an ODRL Party
type Party struct {
	// A collection of parties
	PartyCollection string `json:"odrl:PartyCollection,omitempty"`
	// Party assigned a responsibility
	Assignee interface{} `json:"odrl:assignee,omitempty"`
	// Party assigning a responsibility
	Assigner interface{} `json:"odrl:assigner,omitempty"`
	// Role of assigner in a policy
	AssignerOf Policy `json:"odrl:assignerOf,omitempty"`
	// Role of assignee in a policy
	AssigneeOf Policy `json:"odrl:assigneeOf,omitempty"`
	// Unique identifier for the party
	UID string `json:"odrl:uid,omitempty"`
}

// Permission represents an ODRL Permission
type Permission struct {
	Rule
	// Defines a permission
	Permission Rule `json:"odrl:permission,omitempty"`
	// Target of the permission
	Target interface{} `json:"odrl:target"`
}

// Prohibition represents an ODRL Prohibition
type Prohibition struct {
	Rule
	// Defines a prohibition
	Prohibition Rule `json:"odrl:prohibition,omitempty"`
	// Target of the prohibition
	Target interface{} `json:"odrl:target"`
}

// Duty represents an ODRL Duty
type Duty struct {
	Rule
	// Defines an obligation
	Obligation Rule `json:"odrl:obligation,omitempty"`
	// Defines a duty
	Duty Rule `json:"odrl:duty,omitempty"`
	// Defines a consequence
	Consequence string `json:"odrl:consequence,omitempty"`
	// Defines a remedy for unmet duties
	Remedy string `json:"odrl:remedy,omitempty"`
	// Target of the duty
	Target interface{} `json:"odrl:target,omitempty"`
}

// Constraint represents an ODRL Constraint
type Constraint struct {
	// A constraint refinement
	Refinement string `json:"odrl:refinement,omitempty"`
	// Constraint operator
	Operator string `json:"odrl:operator,omitempty"`
	// Right operand in constraint
	RightOperand string `json:"odrl:rightOperand,omitempty"`
	// Reference to the right operand
	RightOperandReference string `json:"odrl:rightOperandReference,omitempty"`
	// Left operand
	LeftOperand string `json:"odrl:leftOperand,omitempty"`
}

// LogicalConstraint represents an ODRL Logical Constraint
type LogicalConstraint struct {
	// Logical operand used in constraints
	Operand string `json:"odrl:operand,omitempty"`
}

// ConstraintOperands represents ODRL Logical Constraint Operands
type ConstraintOperands struct {
	// Or operand
	Or interface{} `json:"odrl:or,omitempty"`
	// Logical XOR operand
	Xone interface{} `json:"odrl:xone,omitempty"`
	// And operand
	And interface{} `json:"odrl:and,omitempty"`
	// Logical AND sequence operand
	AndSequence interface{} `json:"odrl:andSequence,omitempty"`
}

// ConstraintOperators represents ODRL Constraint Operators
type ConstraintOperators struct {
	// Equals operator
	Eq string `json:"odrl:eq,omitempty"`
	// Greater than operator
	Gt string `json:"odrl:gt,omitempty"`
	// Greater than or equal to operator
	Gteq string `json:"odrl:gteq,omitempty"`
	// Less than operator
	Lt string `json:"odrl:lt,omitempty"`
	// Less than or equal to operator
	Lteq string `json:"odrl:lteq,omitempty"`
	// Not equal to operator
	Neq string `json:"odrl:neq,omitempty"`
	// Relationship of type
	IsA string `json:"odrl:isA,omitempty"`
	// Has part relationship
	HasPart string `json:"odrl:hasPart,omitempty"`
	// Is part of relationship
	IsPartOf string `json:"odrl:isPartOf,omitempty"`
	// Is all of a set relationship
	IsAllOf string `json:"odrl:isAllOf,omitempty"`
	// Is any of a relationship
	IsAnyOf string `json:"odrl:isAnyOf,omitempty"`
	// Is none of a relationship
	IsNoneOf string `json:"odrl:isNoneOf,omitempty"`
}

type DataLicense struct {
	// A list of URIs to license documents
	Licenses []string `json:"gx:licenses,omitempty"`
	//required: A resolvable link to the Terms and Conditions applying to that service
	TermsAndConditions string `json:"gx:termsAndConditions,omitempty"`
}

type DataProductDescription struct {
	GaiaXEntity
	DataLicense DataLicense `json:"gx:dataLicense"`
}

// DataProduct represents a Gaia-X data product
type DataProduct struct {
	ServiceOffering
	// required: A resolvable link to the Data Producer Declaration
	ProvidedBy LegalPerson `json:"gx:providedBy"`
	// required: The link to a Data Product Description
	DescribedBy DataProductDescription `json:"gx:describedBy"`
}

// SignatureCheckType defines signature requirements
type SignatureCheckType struct {
	GaiaXEntity
	// Establishes a unique way to identify the participant that has to Sign
	ParticipantRole string `json:"gx:participantRole"`
	// Establishes if a Signature is mandatory or Optional
	Mandatory string `json:"gx:mandatory"`
	// Establishes if the Legal validity check needs to be enforced
	LegalValidity bool `json:"gx:legalValidity"`
}

// DataUsage tracks data usage for a data product
type DataUsage struct {
	GaiaXEntity
	// Link to the Logging Service
	LoggingService string `json:"gx:loggingService,omitempty"`
}

// DataProductUsageContract defines a contract for data product usage
type DataProductUsageContract struct {
	GaiaXEntity
	// A resolvable link to the Data Provider Declaration
	ProvidedBy DataProvider `json:"gx:providedBy"`
	// A resolvable link to the Data Consumer Declaration
	ConsumedBy DataConsumer `json:"gx:consumedBy"`
	// A resolvable link to the Data Product Description Declaration
	DataProduct DataProduct `json:"gx:dataProduct"`
	// The array identifying all required Participant signature
	Signers []SignatureCheckType `json:"gx:signers"`
	// A resolvable link to the Term of Usage
	TermOfUsage string `json:"gx:termOfUsage"`
	// A resolvable link to the Notarization service
	NotarizedIn string `json:"gx:notarizedIn,omitempty"`
	// A resolvable link to Data Usage
	DataUsage DataUsage `json:"gx:dataUsage"`
}

// DataUsageAgreement defines data usage agreement terms
type DataUsageAgreement struct {
	// Designates the producer of a concept
	ProducedBy DataProducer `json:"gx:producedBy"`
	// A resolvable link to the Data Provider
	ProvidedBy DataProvider `json:"gx:providedBy"`
	// A resolvable links to Data Licensors
	LicensedBy []string `json:"gx:licensedBy,omitempty"`
	// A resolvable link to the Data Usage Agreement Trust Anchor
	DataUsageAgreementTrustAnchor string `json:"gx:dataUsageAgreementTrustAnchor"`
	// A resolvable link to the Data Product Description Declaration
	DataProduct DataProduct `json:"gx:dataProduct"`
	// The array identifying all required Participant signature
	Signers []SignatureCheckType `json:"gx:signers"`
}

// DataSet represents a data set in Gaia-X
type DataSet struct {
	GaiaXEntity
	// Title of the Dataset
	Title string `json:"dct:title"`
	// List of distributions format of the dataset
	Distributions []Distribution `json:"dct:distributions"`
	// Unique UUID4
	Identifier string `json:"dct:identifier"`
	// Publication date in ISO 8601 format
	Issued string `json:"dct:issued,omitempty"`
	// Date time in ISO 8601 format after which data is expired
	ExpirationDateTime time.Time `json:"gx:expirationDateTime,omitempty"`
	// A list of URIs to license documents
	Licenses []string `json:"dct:licenses,omitempty"`
	// A list of Licensors
	DataLicensors []DataLicensor `json:"gx:dataLicensors,omitempty"`
	// List of authorizations from the data subjects as Natural Person
	DataUsageAgreements []DataUsageAgreement `json:"gx:dataUsageAgreements,omitempty"`
	// A resolvable link to the data exchange component that exposes the Data Product
	ExposedThrough string `json:"gx:exposedThrough"`
}

// Distribution represents a dataset distribution
type Distribution struct {
	GaiaXEntity
	// Title of the Distribution
	Title string `json:"dct:title"`
	// Format of the dataset distribution (PDF, CSV, …)
	Format string `json:"dct:format"`
	// The compression format of the distribution
	CompressFormat string `json:"dcat:compressFormat,omitempty"`
	// The package format of the distribution
	PackageFormat string `json:"dcat:packageFormat,omitempty"`
	// Size of the dataset distribution
	ByteSize string `json:"dcat:byteSize,omitempty"`
	// List of dataset storage locations
	Locations []string `json:"gx:locations,omitempty"`
	// SHA-256 hash of the document
	Hash string `json:"gx:hash,omitempty"`
	// Algorithm used to create the hash
	HashAlgorithm string `json:"gx:hashAlgorithm,omitempty"`
	// Publication date in ISO 8601 format
	Issued string `json:"dct:issued,omitempty"`
	// Date time in ISO 8601 format after which data is expired
	ExpirationDateTime time.Time `json:"gx:expirationDateTime,omitempty"`
	// Language
	Language string `json:"dct:language,omitempty"`
	// A list of URIs to license documents
	Licenses []string `json:"dct:licenses,omitempty"`
	// A list of Licensors
	DataLicensors []DataLicensor `json:"gx:dataLicensors,omitempty"`
	// List of authorizations from the data subjects as Natural Person
	DataUsageAgreements []DataUsageAgreement `json:"gx:dataUsageAgreements,omitempty"`
}

// DataProvider is equivalent to Gaia-X Provider
type DataProvider struct {
	LegalPerson
}

// DataLicensor is equivalent to Gaia-X Licensor
type DataLicensor struct {
	LegalPerson
}

// DataProducer is equivalent to Gaia-X ResourceOwner
type DataProducer struct {
	LegalPerson
}

// DataConsumer is equivalent to Gaia-X Consumer
type DataConsumer struct {
	LegalPerson
}

// Federator is equivalent to Gaia-X Federator
type Federator struct {
	LegalPerson
}

// LegitimateInterest describes reasons for processing PII
type LegitimateInterest struct {
	// Reasons to process PII as detailed in your personal data protection regime
	LegalBasis string `json:"gx:legalBasis"`
	// A URL pointing to a contact form or an email address
	DataProtectionContact string `json:"gx:dataProtectionContact"`
}
