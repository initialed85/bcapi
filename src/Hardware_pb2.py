# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: Hardware.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='Hardware.proto',
  package='',
  serialized_pb=_b('\n\x0eHardware.proto\"q\n\x08Hardware\x12\x0e\n\x06serial\x18\x01 \x01(\t\x12\x0f\n\x07profile\x18\x02 \x01(\t\x12\r\n\x05imkey\x18\x03 \x01(\t\x12\x0c\n\x04\x64\x61te\x18\x04 \x01(\t\x12\x12\n\nv10factory\x18\x05 \x01(\x0c\x12\x13\n\x0b\x63ountrycode\x18\x06 \x01(\rB+\n\x17\x63om.rajant.bcapi.protosB\x0eHardwareProtosH\x02')
)
_sym_db.RegisterFileDescriptor(DESCRIPTOR)




_HARDWARE = _descriptor.Descriptor(
  name='Hardware',
  full_name='Hardware',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='serial', full_name='Hardware.serial', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='profile', full_name='Hardware.profile', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='imkey', full_name='Hardware.imkey', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='date', full_name='Hardware.date', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='v10factory', full_name='Hardware.v10factory', index=4,
      number=5, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='countrycode', full_name='Hardware.countrycode', index=5,
      number=6, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=18,
  serialized_end=131,
)

DESCRIPTOR.message_types_by_name['Hardware'] = _HARDWARE

Hardware = _reflection.GeneratedProtocolMessageType('Hardware', (_message.Message,), dict(
  DESCRIPTOR = _HARDWARE,
  __module__ = 'Hardware_pb2'
  # @@protoc_insertion_point(class_scope:Hardware)
  ))
_sym_db.RegisterMessage(Hardware)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('\n\027com.rajant.bcapi.protosB\016HardwareProtosH\002'))
# @@protoc_insertion_point(module_scope)
