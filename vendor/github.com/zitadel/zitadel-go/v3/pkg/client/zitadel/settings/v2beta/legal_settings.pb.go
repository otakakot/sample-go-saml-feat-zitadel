// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.25.1
// source: zitadel/settings/v2beta/legal_settings.proto

package settings

import (
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type LegalAndSupportSettings struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TosLink           string `protobuf:"bytes,1,opt,name=tos_link,json=tosLink,proto3" json:"tos_link,omitempty"`
	PrivacyPolicyLink string `protobuf:"bytes,2,opt,name=privacy_policy_link,json=privacyPolicyLink,proto3" json:"privacy_policy_link,omitempty"`
	HelpLink          string `protobuf:"bytes,3,opt,name=help_link,json=helpLink,proto3" json:"help_link,omitempty"`
	SupportEmail      string `protobuf:"bytes,4,opt,name=support_email,json=supportEmail,proto3" json:"support_email,omitempty"`
	// resource_owner_type returns if the setting is managed on the organization or on the instance
	ResourceOwnerType ResourceOwnerType `protobuf:"varint,5,opt,name=resource_owner_type,json=resourceOwnerType,proto3,enum=zitadel.settings.v2beta.ResourceOwnerType" json:"resource_owner_type,omitempty"`
	DocsLink          string            `protobuf:"bytes,6,opt,name=docs_link,json=docsLink,proto3" json:"docs_link,omitempty"`
	CustomLink        string            `protobuf:"bytes,7,opt,name=custom_link,json=customLink,proto3" json:"custom_link,omitempty"`
	CustomLinkText    string            `protobuf:"bytes,8,opt,name=custom_link_text,json=customLinkText,proto3" json:"custom_link_text,omitempty"`
}

func (x *LegalAndSupportSettings) Reset() {
	*x = LegalAndSupportSettings{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_settings_v2beta_legal_settings_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LegalAndSupportSettings) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LegalAndSupportSettings) ProtoMessage() {}

func (x *LegalAndSupportSettings) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_settings_v2beta_legal_settings_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LegalAndSupportSettings.ProtoReflect.Descriptor instead.
func (*LegalAndSupportSettings) Descriptor() ([]byte, []int) {
	return file_zitadel_settings_v2beta_legal_settings_proto_rawDescGZIP(), []int{0}
}

func (x *LegalAndSupportSettings) GetTosLink() string {
	if x != nil {
		return x.TosLink
	}
	return ""
}

func (x *LegalAndSupportSettings) GetPrivacyPolicyLink() string {
	if x != nil {
		return x.PrivacyPolicyLink
	}
	return ""
}

func (x *LegalAndSupportSettings) GetHelpLink() string {
	if x != nil {
		return x.HelpLink
	}
	return ""
}

func (x *LegalAndSupportSettings) GetSupportEmail() string {
	if x != nil {
		return x.SupportEmail
	}
	return ""
}

func (x *LegalAndSupportSettings) GetResourceOwnerType() ResourceOwnerType {
	if x != nil {
		return x.ResourceOwnerType
	}
	return ResourceOwnerType_RESOURCE_OWNER_TYPE_UNSPECIFIED
}

func (x *LegalAndSupportSettings) GetDocsLink() string {
	if x != nil {
		return x.DocsLink
	}
	return ""
}

func (x *LegalAndSupportSettings) GetCustomLink() string {
	if x != nil {
		return x.CustomLink
	}
	return ""
}

func (x *LegalAndSupportSettings) GetCustomLinkText() string {
	if x != nil {
		return x.CustomLinkText
	}
	return ""
}

var File_zitadel_settings_v2beta_legal_settings_proto protoreflect.FileDescriptor

var file_zitadel_settings_v2beta_legal_settings_proto_rawDesc = []byte{
	0x0a, 0x2c, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e,
	0x67, 0x73, 0x2f, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61, 0x2f, 0x6c, 0x65, 0x67, 0x61, 0x6c, 0x5f,
	0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x17,
	0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73,
	0x2e, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61, 0x1a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x2d,
	0x67, 0x65, 0x6e, 0x2d, 0x6f, 0x70, 0x65, 0x6e, 0x61, 0x70, 0x69, 0x76, 0x32, 0x2f, 0x6f, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x26, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c,
	0x2f, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x2f, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61,
	0x2f, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61,
	0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd9, 0x07, 0x0a, 0x17, 0x4c, 0x65, 0x67,
	0x61, 0x6c, 0x41, 0x6e, 0x64, 0x53, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x53, 0x65, 0x74, 0x74,
	0x69, 0x6e, 0x67, 0x73, 0x12, 0x51, 0x0a, 0x08, 0x74, 0x6f, 0x73, 0x5f, 0x6c, 0x69, 0x6e, 0x6b,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x36, 0x92, 0x41, 0x33, 0x4a, 0x31, 0x22, 0x68, 0x74,
	0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x64, 0x6f, 0x63, 0x73, 0x2f, 0x6c, 0x65, 0x67, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x72,
	0x6d, 0x73, 0x2d, 0x6f, 0x66, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x22, 0x52, 0x07,
	0x74, 0x6f, 0x73, 0x4c, 0x69, 0x6e, 0x6b, 0x12, 0x64, 0x0a, 0x13, 0x70, 0x72, 0x69, 0x76, 0x61,
	0x63, 0x79, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x5f, 0x6c, 0x69, 0x6e, 0x6b, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x34, 0x92, 0x41, 0x31, 0x4a, 0x2f, 0x22, 0x68, 0x74, 0x74, 0x70,
	0x73, 0x3a, 0x2f, 0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x64, 0x6f, 0x63, 0x73, 0x2f, 0x6c, 0x65, 0x67, 0x61, 0x6c, 0x2f, 0x70, 0x72, 0x69, 0x76, 0x61,
	0x63, 0x79, 0x2d, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x22, 0x52, 0x11, 0x70, 0x72, 0x69, 0x76,
	0x61, 0x63, 0x79, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x4c, 0x69, 0x6e, 0x6b, 0x12, 0x51, 0x0a,
	0x09, 0x68, 0x65, 0x6c, 0x70, 0x5f, 0x6c, 0x69, 0x6e, 0x6b, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x42, 0x34, 0x92, 0x41, 0x31, 0x4a, 0x2f, 0x22, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f,
	0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x64, 0x6f, 0x63, 0x73,
	0x2f, 0x6d, 0x61, 0x6e, 0x75, 0x61, 0x6c, 0x73, 0x2f, 0x69, 0x6e, 0x74, 0x72, 0x6f, 0x64, 0x75,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x52, 0x08, 0x68, 0x65, 0x6c, 0x70, 0x4c, 0x69, 0x6e, 0x6b,
	0x12, 0x6e, 0x0a, 0x0d, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x65, 0x6d, 0x61, 0x69,
	0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x42, 0x49, 0x92, 0x41, 0x39, 0x32, 0x1d, 0x68, 0x65,
	0x6c, 0x70, 0x20, 0x2f, 0x20, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x20, 0x65, 0x6d, 0x61,
	0x69, 0x6c, 0x20, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x2e, 0x4a, 0x18, 0x22, 0x73, 0x75,
	0x70, 0x70, 0x6f, 0x72, 0x74, 0x2d, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x40, 0x74, 0x65, 0x73, 0x74,
	0x2e, 0x63, 0x6f, 0x6d, 0x22, 0xfa, 0x42, 0x0a, 0x72, 0x08, 0x18, 0xc0, 0x02, 0xd0, 0x01, 0x01,
	0x60, 0x01, 0x52, 0x0c, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x45, 0x6d, 0x61, 0x69, 0x6c,
	0x12, 0xbd, 0x01, 0x0a, 0x13, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x6f, 0x77,
	0x6e, 0x65, 0x72, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x2a,
	0x2e, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67,
	0x73, 0x2e, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x4f, 0x77, 0x6e, 0x65, 0x72, 0x54, 0x79, 0x70, 0x65, 0x42, 0x61, 0x92, 0x41, 0x5e, 0x32,
	0x5c, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x5f,
	0x74, 0x79, 0x70, 0x65, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x73, 0x20, 0x69, 0x66, 0x20,
	0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x69, 0x73, 0x20, 0x6d,
	0x61, 0x6e, 0x61, 0x67, 0x65, 0x64, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6f, 0x72,
	0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x6f, 0x72, 0x20, 0x6f, 0x6e,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x52, 0x11, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4f, 0x77, 0x6e, 0x65, 0x72, 0x54, 0x79, 0x70, 0x65,
	0x12, 0x6f, 0x0a, 0x09, 0x64, 0x6f, 0x63, 0x73, 0x5f, 0x6c, 0x69, 0x6e, 0x6b, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x09, 0x42, 0x52, 0x92, 0x41, 0x4f, 0x32, 0x31, 0x4c, 0x69, 0x6e, 0x6b, 0x20, 0x74,
	0x6f, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20,
	0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x73, 0x68, 0x6f, 0x77, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x74,
	0x68, 0x65, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x2e, 0x4a, 0x1a, 0x22, 0x68, 0x74,
	0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x64, 0x6f, 0x63, 0x73, 0x22, 0x52, 0x08, 0x64, 0x6f, 0x63, 0x73, 0x4c, 0x69, 0x6e,
	0x6b, 0x12, 0x8b, 0x01, 0x0a, 0x0b, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6c, 0x69, 0x6e,
	0x6b, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x42, 0x6a, 0x92, 0x41, 0x67, 0x32, 0x4c, 0x4c, 0x69,
	0x6e, 0x6b, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x6e, 0x20, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61,
	0x6c, 0x20, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20,
	0x77, 0x69, 0x6c, 0x6c, 0x20, 0x62, 0x65, 0x20, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c,
	0x65, 0x20, 0x74, 0x6f, 0x20, 0x75, 0x73, 0x65, 0x72, 0x73, 0x20, 0x69, 0x6e, 0x20, 0x74, 0x68,
	0x65, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x2e, 0x4a, 0x17, 0x22, 0x68, 0x74, 0x74,
	0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2e, 0x6c, 0x69,
	0x6e, 0x6b, 0x22, 0x52, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x4c, 0x69, 0x6e, 0x6b, 0x12,
	0x82, 0x01, 0x0a, 0x10, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6c, 0x69, 0x6e, 0x6b, 0x5f,
	0x74, 0x65, 0x78, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x42, 0x58, 0x92, 0x41, 0x55, 0x32,
	0x47, 0x54, 0x68, 0x65, 0x20, 0x62, 0x75, 0x74, 0x74, 0x6f, 0x6e, 0x20, 0x74, 0x65, 0x78, 0x74,
	0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x73,
	0x68, 0x6f, 0x77, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x20,
	0x70, 0x6f, 0x69, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x74, 0x6f, 0x20, 0x63, 0x75, 0x73, 0x74,
	0x6f, 0x6d, 0x20, 0x6c, 0x69, 0x6e, 0x6b, 0x2e, 0x4a, 0x0a, 0x22, 0x45, 0x78, 0x74, 0x65, 0x72,
	0x6e, 0x61, 0x6c, 0x22, 0x52, 0x0e, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x4c, 0x69, 0x6e, 0x6b,
	0x54, 0x65, 0x78, 0x74, 0x42, 0x3e, 0x5a, 0x3c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64,
	0x65, 0x6c, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x73, 0x65, 0x74, 0x74,
	0x69, 0x6e, 0x67, 0x73, 0x2f, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61, 0x3b, 0x73, 0x65, 0x74, 0x74,
	0x69, 0x6e, 0x67, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_zitadel_settings_v2beta_legal_settings_proto_rawDescOnce sync.Once
	file_zitadel_settings_v2beta_legal_settings_proto_rawDescData = file_zitadel_settings_v2beta_legal_settings_proto_rawDesc
)

func file_zitadel_settings_v2beta_legal_settings_proto_rawDescGZIP() []byte {
	file_zitadel_settings_v2beta_legal_settings_proto_rawDescOnce.Do(func() {
		file_zitadel_settings_v2beta_legal_settings_proto_rawDescData = protoimpl.X.CompressGZIP(file_zitadel_settings_v2beta_legal_settings_proto_rawDescData)
	})
	return file_zitadel_settings_v2beta_legal_settings_proto_rawDescData
}

var file_zitadel_settings_v2beta_legal_settings_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_zitadel_settings_v2beta_legal_settings_proto_goTypes = []interface{}{
	(*LegalAndSupportSettings)(nil), // 0: zitadel.settings.v2beta.LegalAndSupportSettings
	(ResourceOwnerType)(0),          // 1: zitadel.settings.v2beta.ResourceOwnerType
}
var file_zitadel_settings_v2beta_legal_settings_proto_depIdxs = []int32{
	1, // 0: zitadel.settings.v2beta.LegalAndSupportSettings.resource_owner_type:type_name -> zitadel.settings.v2beta.ResourceOwnerType
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_zitadel_settings_v2beta_legal_settings_proto_init() }
func file_zitadel_settings_v2beta_legal_settings_proto_init() {
	if File_zitadel_settings_v2beta_legal_settings_proto != nil {
		return
	}
	file_zitadel_settings_v2beta_settings_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_zitadel_settings_v2beta_legal_settings_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LegalAndSupportSettings); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_zitadel_settings_v2beta_legal_settings_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_zitadel_settings_v2beta_legal_settings_proto_goTypes,
		DependencyIndexes: file_zitadel_settings_v2beta_legal_settings_proto_depIdxs,
		MessageInfos:      file_zitadel_settings_v2beta_legal_settings_proto_msgTypes,
	}.Build()
	File_zitadel_settings_v2beta_legal_settings_proto = out.File
	file_zitadel_settings_v2beta_legal_settings_proto_rawDesc = nil
	file_zitadel_settings_v2beta_legal_settings_proto_goTypes = nil
	file_zitadel_settings_v2beta_legal_settings_proto_depIdxs = nil
}
