#!/usr/bin/env python3
import os
import hashlib
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import cpu_count
from enlighten import get_manager

from . import mtio
from . import update_metadata_pb2 as um
from .update_metadata_pb2 import InstallOperation
from .ziputil import get_zip_stored_entry_offset
from .future_util import wait_interruptible


def u32(x):
    from struct import unpack
    return unpack(">I", x)[0]

def u64(x):
    from struct import unpack
    return unpack(">Q", x)[0]


class Dumper:
    """Raw OTA extractor with no decompress and no zero padding"""
    def __init__(self, payloadfile, out, old=None, images="", workers=cpu_count(), list_partitions=False, extract_metadata=False):
        self.payloadfile: mtio.MTIOBase = payloadfile
        self.manager = get_manager()
        self.out = out
        self.old_dir = old
        self.images = images
        self.workers = workers
        self.list_partitions = list_partitions
        self.extract_metadata = extract_metadata

        try:
            off, _ = get_zip_stored_entry_offset(self.payloadfile, "payload.bin")
            self.base_off = off
        except:
            self.base_off = 0

        self.parse_metadata()
        if self.list_partitions:
            self.list_partitions_info()

    def parse_metadata(self):
        head_len = 4 + 8 + 8 + 4
        fp = self.base_off
        header = self.payloadfile.read(fp, head_len)
        fp += head_len
        assert header[:4] == b"CrAU"
        assert u64(header[4:12]) == 2
        manifest_size = u64(header[12:20])
        sig_size = u32(header[20:24])
        manifest = self.payloadfile.read(fp, manifest_size)
        fp += manifest_size + sig_size
        self.data_offset = fp - self.base_off
        self.dam = um.DeltaArchiveManifest()
        self.dam.ParseFromString(manifest)
        self.block_size = self.dam.block_size

    def run(self):
        if self.list_partitions or self.extract_metadata:
            return

        partitions = self.dam.partitions
        if self.images:
            partitions = [p for p in partitions if p.partition_name in self.images.split(",")]

        partitions_with_ops = []
        for partition in partitions:
            ops = []
            for op in partition.operations:
                ops.append({
                    "operation": op,
                    "offset": self.data_offset + op.data_offset,
                    "length": op.data_length,
                })
            partitions_with_ops.append({
                "partition": partition,
                "operations": ops,
            })

        self.multiprocess_partitions(partitions_with_ops)
        self.manager.stop()
        self.payloadfile.close()

    def multiprocess_partitions(self, partitions):
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            for part in partitions:
                partition_name = part["partition"].partition_name
                bar = self.manager.counter(total=len(part["operations"]), desc=partition_name, unit="ops")
                out_file = mtio.MTFile(os.path.join(self.out, f"{partition_name}.raw"), "w")
                old_file = None
                if self.old_dir:
                    old_path = os.path.join(self.old_dir, f"{partition_name}.img")
                    if os.path.exists(old_path):
                        old_file = mtio.MTFile(old_path, "r")

                tasks = []
                for op in part["operations"]:
                    tasks.append(
                        executor.submit(self.do_op, op, out_file, old_file, bar)
                    )
                done, _ = wait_interruptible(tasks, return_when='FIRST_EXCEPTION')
                for t in done:
                    if t.exception():
                        raise t.exception()
                out_file.close()
                if old_file:
                    old_file.close()
                bar.close()

    def do_op(self, op_entry, out_file, old_file, bar):
        op = op_entry["operation"]
        offset = op_entry["offset"]
        length = op_entry["length"]

        if op.type in (InstallOperation.REPLACE, InstallOperation.REPLACE_BZ, InstallOperation.REPLACE_XZ, InstallOperation.ZSTD):
            # write raw bytes, no decompression
            data = self.payloadfile.read(self.base_off + offset, length)
            out_file.write(op.dst_extents[0].start_block * self.block_size, data)

        elif op.type == InstallOperation.SOURCE_COPY:
            if not old_file:
                raise RuntimeError(f"SOURCE_COPY requires old partition")
            copied_data = b""
            for src_ext in op.src_extents:
                copied_data += old_file.read(src_ext.start_block * self.block_size, src_ext.num_blocks * self.block_size)
            out_file.write(op.dst_extents[0].start_block * self.block_size, copied_data)

        elif op.type == InstallOperation.ZERO:
            for ext in op.dst_extents:
                out_file.write(ext.start_block * self.block_size, b"\x00" * ext.num_blocks * self.block_size)
        else:
            raise ValueError(f"Unsupported operation type {op.type}")
        bar.update(1)

    def list_partitions_info(self):
        info = []
        for p in self.dam.partitions:
            blocks = sum(ext.num_blocks for op in p.operations for ext in op.dst_extents)
            size = blocks * self.block_size
            info.append({
                "partition_name": p.partition_name,
                "size_bytes": size,
                "hash": p.new_partition_info.hash.hex()
            })
        out_file = os.path.join(self.out, "partitions_info.json")
        with open(out_file, "w") as f:
            import json
            json.dump(info, f, indent=4)
        print(f"Partitions info written to {out_file}")