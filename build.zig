const std = @import("std");
const version = @import("version.zig");
const builtin = std.builtin;

pub fn build(b: *std.build.Builder) void {

    b.setPreferredReleaseMode(builtin.Mode.ReleaseSafe);
    const mode = b.standardReleaseOptions();
    

    const lib = b.addStaticLibrary("gost", "gosthash.zig");
    _ = b.version(version.major, version.minor, version.patch);
    lib.setBuildMode(mode);
    lib.install();

    var main_tests = b.addTest("gosthash.zig");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
