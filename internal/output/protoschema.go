package output

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// ProtoSchemas are the protobuf schemas --proto gives, for decoding gRPC
// messages with their fields' names: compiled descriptor sets, as
// `protoc --descriptor_set_out=FILE --include_imports` or `buf build -o FILE`
// write them. snoopy doesn't parse .proto files, which would need their
// imports found and resolved as protoc does.
type ProtoSchemas struct {
	files *protoregistry.Files
	// methods is how many methods the schemas have, for saying so.
	methods int
}

// LoadProtoSchemas reads descriptor sets. Files may depend on files in
// other sets given, but not on files none of them has.
func LoadProtoSchemas(paths []string) (*ProtoSchemas, error) {
	set := &descriptorpb.FileDescriptorSet{}
	seen := map[string]bool{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var one descriptorpb.FileDescriptorSet
		if err := proto.Unmarshal(data, &one); err != nil || len(one.File) == 0 {
			return nil, fmt.Errorf("%s isn't a protobuf descriptor set; make one with protoc --descriptor_set_out=%[1]s --include_imports, or buf build -o %[1]s", path)
		}
		for _, f := range one.File {
			if !seen[f.GetName()] {
				seen[f.GetName()] = true
				set.File = append(set.File, f)
			}
		}
	}
	files, err := protodesc.NewFiles(set)
	if err != nil {
		var missing string
		if strings.Contains(err.Error(), "not found") {
			missing = " (one it imports is missing: protoc needs --include_imports)"
		}
		return nil, fmt.Errorf("%s: %w%s", strings.Join(paths, ", "), err, missing)
	}
	s := &ProtoSchemas{files: files}
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		for i := 0; i < fd.Services().Len(); i++ {
			s.methods += fd.Services().Get(i).Methods().Len()
		}
		return true
	})
	if s.methods == 0 {
		return nil, errors.New("--proto: the descriptor sets have no services, so no gRPC method to decode messages of")
	}
	return s, nil
}

// Methods returns how many gRPC methods the schemas describe.
func (s *ProtoSchemas) Methods() int { return s.methods }

// message returns the type of a gRPC method's requests, or of its
// responses, from its path (/package.Service/Method), or nil if the
// schemas don't have it.
func (s *ProtoSchemas) message(path string, request bool) protoreflect.MessageDescriptor {
	service, method, ok := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	if s == nil || !ok {
		return nil
	}
	d, err := s.files.FindDescriptorByName(protoreflect.FullName(service))
	if err != nil {
		return nil
	}
	sd, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil
	}
	md := sd.Methods().ByName(protoreflect.Name(method))
	if md == nil {
		return nil
	}
	if request {
		return md.Input()
	}
	return md.Output()
}

// decodeTyped decodes a message of type md, a line per field as protoc
// --decode shows it: names, enums by name, nested messages indented.
// (prototext's output is made to vary between runs, on purpose.)
func decodeTyped(md protoreflect.MessageDescriptor, b []byte) ([]string, error) {
	m := dynamicpb.NewMessage(md)
	if err := proto.Unmarshal(b, m); err != nil {
		return nil, err
	}
	lines := []string{}
	writeMessage(&lines, m, "", 0)
	return lines, nil
}

func writeMessage(lines *[]string, m protoreflect.Message, indent string, depth int) {
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ { // in the order the schema has them
		fd := fields.Get(i)
		if !m.Has(fd) {
			continue
		}
		v := m.Get(fd)
		switch {
		case fd.IsList():
			l := v.List()
			for j := 0; j < l.Len(); j++ {
				writeField(lines, string(fd.Name()), fd, l.Get(j), indent, depth)
			}
		case fd.IsMap():
			// In key order, so the output doesn't vary.
			type entry struct {
				k protoreflect.MapKey
				v protoreflect.Value
			}
			var entries []entry
			v.Map().Range(func(k protoreflect.MapKey, v protoreflect.Value) bool {
				entries = append(entries, entry{k, v})
				return true
			})
			slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.k.String(), b.k.String()) })
			for _, e := range entries {
				*lines = append(*lines, indent+string(fd.Name())+" {")
				writeField(lines, "key", fd.MapKey(), e.k.Value(), indent+"  ", depth+1)
				writeField(lines, "value", fd.MapValue(), e.v, indent+"  ", depth+1)
				*lines = append(*lines, indent+"}")
			}
		default:
			writeField(lines, string(fd.Name()), fd, v, indent, depth)
		}
	}
	// Fields the schema doesn't have (a newer version of it), by number.
	if unknown := m.GetUnknown(); len(unknown) > 0 {
		if raw, ok := decodeProtobuf(unknown, depth); ok {
			for _, l := range raw {
				*lines = append(*lines, indent+l)
			}
		}
	}
}

func writeField(lines *[]string, name string, fd protoreflect.FieldDescriptor, v protoreflect.Value, indent string, depth int) {
	switch fd.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		if depth >= maxProtoDepth {
			*lines = append(*lines, indent+name+" { ... }")
			return
		}
		*lines = append(*lines, indent+name+" {")
		writeMessage(lines, v.Message(), indent+"  ", depth+1)
		*lines = append(*lines, indent+"}")
		return
	}
	*lines = append(*lines, indent+name+": "+scalar(fd, v))
}

// scalar formats a field's value as the text format does.
func scalar(fd protoreflect.FieldDescriptor, v protoreflect.Value) string {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return strconv.Quote(v.String())
	case protoreflect.BytesKind:
		return strconv.Quote(string(v.Bytes()))
	case protoreflect.EnumKind:
		if ev := fd.Enum().Values().ByNumber(v.Enum()); ev != nil {
			return string(ev.Name())
		}
		return strconv.Itoa(int(v.Enum()))
	}
	return v.String()
}
