# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: trace_info.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x10trace_info.proto"t\n\rAssemblerInfo\x12\x11\n\tstatus_ok\x18\x01 \x01(\x08\x12\x10\n\x08\x63ommands\x18\x02 \x03(\t\x12\x13\n\x06output\x18\x03 \x01(\tH\x00\x88\x01\x01\x12\x13\n\x06\x65rrors\x18\x04 \x01(\tH\x01\x88\x01\x01\x42\t\n\x07_outputB\t\n\x07_errors"p\n\nLinkerInfo\x12\x11\n\tstatus_ok\x18\x01 \x01(\x08\x12\x0f\n\x07\x63ommand\x18\x02 \x01(\t\x12\x13\n\x06output\x18\x03 \x01(\tH\x00\x88\x01\x01\x12\x13\n\x06\x65rrors\x18\x04 \x01(\tH\x01\x88\x01\x01\x42\t\n\x07_outputB\t\n\x07_errors"J\n\tBuildInfo\x12\x1f\n\x07\x61s_info\x18\x01 \x01(\x0b\x32\x0e.AssemblerInfo\x12\x1c\n\x07ld_info\x18\x02 \x01(\x0b\x32\x0b.LinkerInfo"3\n\x08LineInfo\x12\x16\n\x0e\x66ilename_index\x18\x01 \x01(\x05\x12\x0f\n\x07linenum\x18\x02 \x01(\x05"\xa8\x03\n\tTraceStep\x12 \n\rline_executed\x18\x01 \x01(\x0b\x32\t.LineInfo\x12\x0e\n\x06stdout\x18\x02 \x01(\x0c\x12\x0e\n\x06stderr\x18\x03 \x01(\t\x12\x16\n\texit_code\x18\x04 \x01(\x11H\x00\x88\x01\x01\x12\x35\n\x0eregister_delta\x18\x05 \x03(\x0b\x32\x1d.TraceStep.RegisterDeltaEntry\x12-\n\nflag_delta\x18\x06 \x03(\x0b\x32\x19.TraceStep.FlagDeltaEntry\x12\x31\n\x0cmemory_delta\x18\x07 \x03(\x0b\x32\x1b.TraceStep.MemoryDeltaEntry\x1a\x34\n\x12RegisterDeltaEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x04:\x02\x38\x01\x1a\x30\n\x0e\x46lagDeltaEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x08:\x02\x38\x01\x1a\x32\n\x10MemoryDeltaEntry\x12\x0b\n\x03key\x18\x01 \x01(\x04\x12\r\n\x05value\x18\x02 \x01(\x0c:\x02\x38\x01\x42\x0c\n\n_exit_code"\xe7\x02\n\x0e\x45xecutionTrace\x12\x0e\n\x06rootfs\x18\x01 \x01(\t\x12\x15\n\rarch_num_bits\x18\x02 \x01(\r\x12\x15\n\rlittle_endian\x18\x03 \x01(\x08\x12\x18\n\x10source_filenames\x18\x04 \x03(\t\x12\x19\n\x05\x62uild\x18\x05 \x01(\x0b\x32\n.BuildInfo\x12\x0c\n\x04\x61rgv\x18\x06 \x01(\t\x12\x16\n\texit_code\x18\x07 \x01(\x11H\x00\x88\x01\x01\x12\x19\n\x11reached_max_steps\x18\x08 \x01(\x08\x12\x19\n\x05steps\x18\t \x03(\x0b\x32\n.TraceStep\x12"\n\x15instructions_executed\x18\n \x01(\x04H\x01\x88\x01\x01\x12!\n\x14instructions_written\x18\x0b \x01(\x04H\x02\x88\x01\x01\x42\x0c\n\n_exit_codeB\x18\n\x16_instructions_executedB\x17\n\x15_instructions_writtenb\x06proto3'
)

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "trace_info_pb2", globals())
if _descriptor._USE_C_DESCRIPTORS == False:

    DESCRIPTOR._options = None
    _TRACESTEP_REGISTERDELTAENTRY._options = None
    _TRACESTEP_REGISTERDELTAENTRY._serialized_options = b"8\001"
    _TRACESTEP_FLAGDELTAENTRY._options = None
    _TRACESTEP_FLAGDELTAENTRY._serialized_options = b"8\001"
    _TRACESTEP_MEMORYDELTAENTRY._options = None
    _TRACESTEP_MEMORYDELTAENTRY._serialized_options = b"8\001"
    _ASSEMBLERINFO._serialized_start = 20
    _ASSEMBLERINFO._serialized_end = 136
    _LINKERINFO._serialized_start = 138
    _LINKERINFO._serialized_end = 250
    _BUILDINFO._serialized_start = 252
    _BUILDINFO._serialized_end = 326
    _LINEINFO._serialized_start = 328
    _LINEINFO._serialized_end = 379
    _TRACESTEP._serialized_start = 382
    _TRACESTEP._serialized_end = 806
    _TRACESTEP_REGISTERDELTAENTRY._serialized_start = 638
    _TRACESTEP_REGISTERDELTAENTRY._serialized_end = 690
    _TRACESTEP_FLAGDELTAENTRY._serialized_start = 692
    _TRACESTEP_FLAGDELTAENTRY._serialized_end = 740
    _TRACESTEP_MEMORYDELTAENTRY._serialized_start = 742
    _TRACESTEP_MEMORYDELTAENTRY._serialized_end = 792
    _EXECUTIONTRACE._serialized_start = 809
    _EXECUTIONTRACE._serialized_end = 1168
# @@protoc_insertion_point(module_scope)
