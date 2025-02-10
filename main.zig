const std = @import("std");
const crypto = std.crypto;
const io = std.io;
const fs = std.fs;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

const hash = crypto.hash.sha2.Sha256;

var rbuf: [1024 * 1024]u8 = undefined;

fn writeChunks(src_file: *fs.File, dest_file: *fs.File, digester: *hash, amount: usize) !void {
    const chunk_count = amount / rbuf.len;
    const remnants = amount % rbuf.len;

    for (0..chunk_count) |_| {
        const n = try src_file.readAll(rbuf[0..]);
        std.debug.assert(n == rbuf.len);
        digester.update(rbuf[0..]);
        try dest_file.writeAll(rbuf[0..]);
    }

    if (remnants > 0) {
        const n = try src_file.readAll(rbuf[0..remnants]);
        std.debug.assert(n == remnants);
        digester.update(rbuf[0..remnants]);
        try dest_file.writeAll(rbuf[0..remnants]);
    }

    try dest_file.writeAll(digester.peek()[0..]);
}

pub fn split(file_name: []const u8, chunk_size: usize, out_folder_name: []const u8) !void {
    const cwd = fs.cwd();
    var file = try cwd.openFile(file_name, .{});

    const file_size = (try file.stat()).size;

    cwd.makeDir(out_folder_name) catch |e| {
        switch (e) {
            error.PathAlreadyExists => {
                std.debug.print("overwrite {s}? [Y/N]\n", .{out_folder_name});
                const answer = try io.getStdIn().reader().readByte();
                if (!(answer == 'Y' or answer == 'y')) {
                    std.debug.print("canceled.\n", .{});
                    std.process.exit(0);
                }
                try cwd.deleteTree(out_folder_name);
                try cwd.makeDir(out_folder_name);
            },
            else => {
                return e;
            },
        }
    };

    var digester = hash.init(.{});
    var chunks_dir = try cwd.openDir(out_folder_name, .{});
    defer chunks_dir.close();
    const total_chunks = (file_size / chunk_size);
    const remnants = file_size % chunk_size;
    std.debug.print("splitting {s} into {s} ({} chunks): ", .{ file_name, out_folder_name, if (remnants > 0) total_chunks + 1 else total_chunks });
    for (0..total_chunks) |i| {
        const chunk_name = try std.fmt.allocPrint(gpa.allocator(), "{s}.{}", .{ file_name, i });
        defer gpa.allocator().free(chunk_name);
        std.debug.print("   [{}] {s}\n", .{ i, chunk_name });
        var chunk_file = try chunks_dir.createFile(chunk_name, .{});
        defer chunk_file.close();
        try writeChunks(&file, &chunk_file, &digester, chunk_size);
        if (i == 0) try chunk_file.writer().writeInt(u64, file_size, .big);
    }

    if (remnants > 0) {
        const chunk_name = try std.fmt.allocPrint(gpa.allocator(), "{s}.{}", .{ file_name, total_chunks });
        defer gpa.allocator().free(chunk_name);
        std.debug.print("   [{}] {s}\n", .{ total_chunks, chunk_name });
        var chunk_file = try chunks_dir.createFile(chunk_name, .{});
        defer chunk_file.close();
        try writeChunks(&file, &chunk_file, &digester, remnants);
    }
}

fn readChunks(src_file: *fs.File, dest_file: *fs.File, digester: *hash, amount: usize) !void {
    const chunk_count = amount / rbuf.len;
    const remnants = amount % rbuf.len;

    for (0..chunk_count) |_| {
        const n = try src_file.readAll(rbuf[0..]);
        std.debug.assert(n == rbuf.len);
        digester.update(rbuf[0..]);
        try dest_file.writeAll(rbuf[0..]);
    }

    if (remnants > 0) {
        const n = try src_file.readAll(rbuf[0..remnants]);
        std.debug.assert(n == remnants);
        digester.update(rbuf[0..remnants]);
        try dest_file.writeAll(rbuf[0..remnants]);
    }

    const n = try src_file.readAll(rbuf[0..hash.digest_length]);
    std.debug.assert(n == hash.digest_length);
    if (!std.mem.eql(u8, digester.peek()[0..], rbuf[0..hash.digest_length])) {
        return error.FileCorrupted;
    }
}

pub fn merge(folder_name: []const u8, orig_file_name: []const u8) !void {
    const cwd = fs.cwd();
    const folder = try cwd.openDir(folder_name, .{});
    var output_file = try cwd.createFile(orig_file_name, .{ .truncate = true });
    var digester = hash.init(.{});

    const file_size, const chunk_size = blk: {
        var file_size: u64 = 0;
        var chunk_size: u64 = 0;
        const chunk_file_name = try std.fmt.allocPrint(gpa.allocator(), "{s}.{}", .{ orig_file_name, 0 });
        defer gpa.allocator().free(chunk_file_name);
        var chunk_file = try folder.openFile(chunk_file_name, .{});
        defer chunk_file.close();
        try chunk_file.seekFromEnd(-8);
        file_size = try chunk_file.reader().readInt(u64, .big);
        try chunk_file.seekBy(-@as(isize, @intCast(hash.digest_length + 8)));
        chunk_size = try chunk_file.getPos();
        break :blk .{ file_size, chunk_size };
    };

    const total_chunks = (file_size / chunk_size);
    const remnants = file_size % chunk_size;
    std.debug.print("merging {} chunks from {s} into {s}: ", .{ if (remnants > 0) total_chunks + 1 else total_chunks, folder_name, orig_file_name });
    for (0..total_chunks) |i| {
        const chunk_name = try std.fmt.allocPrint(gpa.allocator(), "{s}.{}", .{ orig_file_name, i });
        defer gpa.allocator().free(chunk_name);
        std.debug.print("[{}] {s}\n", .{ i, chunk_name });

        var chunk_file = try folder.openFile(chunk_name, .{});
        defer chunk_file.close();

        try readChunks(&chunk_file, &output_file, &digester, chunk_size);
    }

    if (remnants > 0) {
        const chunk_name = try std.fmt.allocPrint(gpa.allocator(), "{s}.{}", .{ orig_file_name, total_chunks });
        defer gpa.allocator().free(chunk_name);
        std.debug.print("[{}] {s}\n", .{ total_chunks, chunk_name });

        var chunk_file = try folder.openFile(chunk_name, .{});
        defer chunk_file.close();

        try readChunks(&chunk_file, &output_file, &digester, remnants);
    }
}

pub fn printHelp() noreturn {
    std.debug.print("Usage: ./bin args\n", .{});
    std.debug.print("   args = (merge | split) + parameters\n", .{});
    std.debug.print("   parameters = args == merge_parameters ? merge_parameters : split_parameters\n", .{});
    std.debug.print("   merge_parameters = source_dir_name + output_file_name\n", .{});
    std.debug.print("   split_parameters = source_file_name + chunk size + output_dir_name\n", .{});
    std.process.exit(1);
}

pub fn main() !void {
    var args = try std.process.argsWithAllocator(gpa.allocator());
    defer args.deinit();

    std.debug.assert(args.skip());

    if (args.next()) |arg| {
        if (std.mem.eql(u8, "split", arg)) {
            const file_name = args.next() orelse printHelp();
            const chunk_size_str = args.next() orelse printHelp();
            const chunk_size = std.fmt.parseInt(u64, chunk_size_str, 10) catch printHelp();
            const out_put_dir = args.next() orelse printHelp();
            split(file_name, chunk_size, out_put_dir) catch |e| {
                std.debug.print("Error: {s}\n", .{@errorName(e)});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, "merge", arg)) {
            const src_dir = args.next() orelse printHelp();
            const file_name = args.next() orelse printHelp();
            merge(src_dir, file_name) catch |e| {
                std.debug.print("Error: {s}\n", .{@errorName(e)});
                std.process.exit(1);
            };
        } else {
            printHelp();
        }
    }
}

