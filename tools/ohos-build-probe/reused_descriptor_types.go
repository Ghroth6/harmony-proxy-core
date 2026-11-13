package main

type DescriptorMetadata struct {
	Observed bool   `json:"observed"`
	Device   string `json:"device"`
	Inode    string `json:"inode"`
	Mode     uint32 `json:"mode"`
	RDevice  string `json:"rdevice"`
}
type TunReceipt struct {
	FD             int                `json:"fd"`
	MetadataBefore DescriptorMetadata `json:"metadataBefore"`
	CloseAttempted bool               `json:"closeAttempted"`
	CloseResult    int                `json:"closeResult"`
	AfterClose     string             `json:"afterClose"`
	MetadataAfter  DescriptorMetadata `json:"metadataAfter"`
}
