const r4os = @import("r4os");

const TYPE_IPV4: u16 = 0x0800;
const TYPE_IPV6: u16 = 0x86DD;
const TYPE_ARP: u16 = 0x0806;
const TYPE_R4OS_DIAG: u16 = 0x88B5;
const MIN_FRAME_SIZE: usize = 60;
const HEADER_SIZE: usize = 14;

comptime {
    if (!@import("builtin").is_test) asm (r4os.technical2.protocolEntriesAsm("neteth_init", "neteth_shutdown", "neteth_query", "neteth_dispatch"));
}

export fn neteth_init(api: *const r4os.technical2.abi.ProtocolApi2) callconv(.c) i32 {
    const view = r4os.technical2.Protocol.init(api) orelse return r4os.abi.network_error_backend;
    const log = view.function("log_info") orelse return r4os.abi.err_no_fn;
    const register = view.function("register_role") orelse return r4os.abi.err_no_fn;
    const status = view.function("set_status") orelse return r4os.abi.err_no_fn;
    log("NETETH.R4P init");
    const registered = register("net.ethernet", @intFromEnum(r4os.abi.ProtocolCategory.net), 0);
    if (registered != 0) return registered;
    return status(@intFromEnum(r4os.abi.ProtocolState.active), "Ethernet-II R4P active");
}

export fn neteth_shutdown() callconv(.c) i32 {
    return 0;
}

export fn neteth_query(out: *r4os.abi.ProtocolStatus) callconv(.c) i32 {
    out.* = .{
        .state = @intFromEnum(r4os.abi.ProtocolState.active),
        .flags = 0,
        .last_error = 0,
        .reserved = 0,
        .note = note("Ethernet-II R4P ready"),
    };
    return 0;
}

export fn neteth_dispatch(op: u32, in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) callconv(.c) i32 {
    _ = out_buffer;
    const request = requestFromBuffer(in_buffer) orelse return -2;
    switch (op) {
        r4os.abi.ethernet_op_handle_rx => handleRx(request),
        r4os.abi.ethernet_op_handle_tx => handleTx(request),
        r4os.abi.ethernet_op_frame_type => frameType(request),
        r4os.abi.ethernet_op_build_diag_frame => buildDiagFrame(request),
        else => return -4,
    }
    return request.result;
}

fn handleRx(request: *r4os.abi.EthernetFrameOp) void {
    request.flags = 0;
    request.ethertype = 0;
    if (request.frame_len < HEADER_SIZE or request.frame_len > request.frame.len) {
        request.result = r4os.abi.ethernet_result_short;
        return;
    }
    const frame = request.frame[0..@intCast(request.frame_len)];
    request.ethertype = readType(frame);
    if (isBroadcast(frame[0..6])) {
        request.flags |= r4os.abi.ethernet_flag_broadcast;
    } else if (isOwn(frame[0..6], request.own_mac)) {
        request.flags |= r4os.abi.ethernet_flag_own_unicast;
    } else if (isIpv6Multicast(frame)) {
        request.flags |= r4os.abi.ethernet_flag_multicast;
    } else {
        request.result = r4os.abi.ethernet_result_filtered;
        return;
    }
    classify(request);
    request.result = r4os.abi.ethernet_result_ok;
}

fn handleTx(request: *r4os.abi.EthernetFrameOp) void {
    request.flags = 0;
    request.ethertype = 0;
    if (request.frame_len < HEADER_SIZE or request.frame_len > request.frame.len) {
        request.result = r4os.abi.ethernet_result_short;
        return;
    }
    const frame = request.frame[0..@intCast(request.frame_len)];
    request.ethertype = readType(frame);
    if (isBroadcast(frame[0..6])) request.flags |= r4os.abi.ethernet_flag_broadcast;
    if (isIpv6Multicast(frame)) request.flags |= r4os.abi.ethernet_flag_multicast;
    classify(request);
    request.result = r4os.abi.ethernet_result_ok;
}

fn frameType(request: *r4os.abi.EthernetFrameOp) void {
    request.flags = 0;
    request.ethertype = 0;
    if (request.frame_len < HEADER_SIZE or request.frame_len > request.frame.len) {
        request.result = r4os.abi.ethernet_result_short;
        return;
    }
    request.ethertype = readType(request.frame[0..@intCast(request.frame_len)]);
    classify(request);
    request.result = r4os.abi.ethernet_result_ok;
}

fn buildDiagFrame(request: *r4os.abi.EthernetFrameOp) void {
    if (request.frame.len < MIN_FRAME_SIZE) {
        request.result = r4os.abi.ethernet_result_buffer_small;
        return;
    }
    var i: usize = 0;
    while (i < MIN_FRAME_SIZE) : (i += 1) request.frame[i] = 0;
    i = 0;
    while (i < 6) : (i += 1) request.frame[i] = 0xFF;
    i = 0;
    while (i < 6) : (i += 1) request.frame[6 + i] = request.source_mac[i];
    request.frame[12] = @intCast(TYPE_R4OS_DIAG >> 8);
    request.frame[13] = @intCast(TYPE_R4OS_DIAG & 0xFF);
    const payload = "R4OS RTL8139 TXDIAG";
    i = 0;
    while (i < payload.len and HEADER_SIZE + i < MIN_FRAME_SIZE) : (i += 1) {
        request.frame[HEADER_SIZE + i] = payload[i];
    }
    request.frame_len = MIN_FRAME_SIZE;
    request.ethertype = TYPE_R4OS_DIAG;
    request.flags = r4os.abi.ethernet_flag_broadcast | r4os.abi.ethernet_flag_r4os_diag;
    request.result = r4os.abi.ethernet_result_ok;
}

fn classify(request: *r4os.abi.EthernetFrameOp) void {
    switch (request.ethertype) {
        TYPE_IPV4 => request.flags |= r4os.abi.ethernet_flag_ipv4,
        TYPE_IPV6 => request.flags |= r4os.abi.ethernet_flag_ipv6,
        TYPE_ARP => request.flags |= r4os.abi.ethernet_flag_arp,
        TYPE_R4OS_DIAG => request.flags |= r4os.abi.ethernet_flag_r4os_diag,
        else => request.flags |= r4os.abi.ethernet_flag_unknown_type,
    }
}

fn requestFromBuffer(buffer: *const r4os.abi.ProtocolBuffer) ?*r4os.abi.EthernetFrameOp {
    // The legacy operation is an exclusive in/out native record, despite
    // the const transport metadata. No packet bytes are native-cast here.
    const native = r4os.native_protocol_view;
    var metadata = buffer.*;
    const view = native.InOut(r4os.abi.EthernetFrameOp).init(&metadata, native.Policy.record(r4os.abi.EthernetFrameOp, .inout, .prefix)) catch return null;
    return view.value;
}

fn readType(frame: []const u8) u16 {
    var reader = r4os.binary_cursor.Reader.init(frame) catch unreachable;
    _ = reader.take(12) catch unreachable;
    return reader.readInt(u16, .big) catch unreachable;
}

fn isIpv6Multicast(frame: []const u8) bool {
    if (frame.len < HEADER_SIZE + 40 or readType(frame) != TYPE_IPV6 or frame[HEADER_SIZE] >> 4 != 6 or frame[0] != 0x33 or frame[1] != 0x33 or frame[HEADER_SIZE + 24] != 0xff) return false;
    var i: usize = 0;
    while (i < 4) : (i += 1) if (frame[2 + i] != frame[HEADER_SIZE + 36 + i]) return false;
    return true;
}

fn isBroadcast(mac: []const u8) bool {
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        if (mac[i] != 0xFF) return false;
    }
    return true;
}

fn isOwn(mac: []const u8, own: [6]u8) bool {
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        if (mac[i] != own[i]) return false;
    }
    return true;
}

fn note(comptime text: []const u8) [64]u8 {
    var out: [64]u8 = .{0} ** 64;
    @memcpy(out[0..text.len], text);
    return out;
}
