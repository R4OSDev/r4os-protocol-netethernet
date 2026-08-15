const r4os = @import("r4os");

const TYPE_IPV4: u16 = 0x0800;
const TYPE_ARP: u16 = 0x0806;
const TYPE_R4OS_DIAG: u16 = 0x88B5;
const MIN_FRAME_SIZE: usize = 60;
const HEADER_SIZE: usize = 14;

comptime {
    asm (r4os.r4dev.protocolEntriesAsm("neteth_init", "neteth_shutdown", "neteth_query", "neteth_dispatch"));
}

export fn neteth_init(api: *const r4os.r4dev.ProtocolApi) callconv(.c) i32 {
    var ctx = r4os.r4dev.ProtocolContext.init(api);
    ctx.logInfo("NETETH.R4P init");
    _ = ctx.registerRole("net.ethernet", .net, 0);
    _ = ctx.setStatus(.active, "Ethernet-II R4P active");
    return 0;
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
        TYPE_ARP => request.flags |= r4os.abi.ethernet_flag_arp,
        TYPE_R4OS_DIAG => request.flags |= r4os.abi.ethernet_flag_r4os_diag,
        else => request.flags |= r4os.abi.ethernet_flag_unknown_type,
    }
}

fn requestFromBuffer(buffer: *const r4os.abi.ProtocolBuffer) ?*r4os.abi.EthernetFrameOp {
    if (buffer.data == null) return null;
    if (buffer.len < @sizeOf(r4os.abi.EthernetFrameOp)) return null;
    return @ptrCast(@alignCast(buffer.data.?));
}

fn readType(frame: []const u8) u16 {
    return (@as(u16, frame[12]) << 8) | @as(u16, frame[13]);
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
