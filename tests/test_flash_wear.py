# tests/test_flash_wear.py
"""
Раздел «Память (flash)»: износ носителя, учёт записи и рычаги снижения
записи (core/flash_wear.py, core/flash_saver.py, api/flash.py).

Железо подменяется деревом ``root`` (/proc и /sys во временном каталоге):
GL.iNet Flint2 — eMMC, ``/overlay`` на loop-устройстве поверх раздела;
типичный NAND-роутер — UBIFS без счётчика записи.
"""

import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from core import flash_saver, flash_wear


def _w(root, rel, text):
    path = os.path.join(root, rel.lstrip("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


class _Root(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="flash-test-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def flint2(self, life="0x02 0x03", pre_eol="0x01", written_sectors=8192):
        r = self.root
        _w(r, "/proc/mounts",
           "/dev/root /rom squashfs ro,relatime 0 0\n"
           "/dev/loop0 /overlay f2fs rw,lazytime,noatime 0 0\n"
           "overlayfs:/overlay / overlay rw,noatime,lowerdir=/ 0 0\n"
           "tmpfs /tmp tmpfs rw,nosuid,nodev,noatime 0 0\n")
        _w(r, "/proc/diskstats",
           " 179  0 mmcblk0 100 0 2000 10 50 0 %d 20 0 0 0\n"
           " 179  5 mmcblk0p5 90 0 1800 10 40 0 %d 20 0 0 0\n"
           "   7  0 loop0 10 0 200 1 30 0 4000 2 0 0 0\n"
           % (written_sectors, written_sectors - 100))
        disk = os.path.join(r, "sys/devices/mmc/mmcblk0")
        os.makedirs(os.path.join(disk, "mmcblk0p5"))
        _w(r, "/sys/devices/mmc/mmcblk0/mmcblk0p5/partition", "5")
        _w(r, "/sys/devices/mmc/mmcblk0/device/type", "MMC")
        _w(r, "/sys/devices/mmc/mmcblk0/device/name", "8GTF4R")
        _w(r, "/sys/devices/mmc/mmcblk0/device/life_time", life)
        _w(r, "/sys/devices/mmc/mmcblk0/device/pre_eol_info", pre_eol)
        _w(r, "/sys/devices/mmc/mmcblk0/size", "15269888")
        os.makedirs(os.path.join(r, "sys/class/block"))
        os.makedirs(os.path.join(r, "sys/block"))
        os.symlink(os.path.join(disk, "mmcblk0p5"),
                   os.path.join(r, "sys/class/block/mmcblk0p5"))
        os.symlink(disk, os.path.join(r, "sys/class/block/mmcblk0"))
        os.symlink(disk, os.path.join(r, "sys/block/mmcblk0"))
        _w(r, "/sys/block/loop0/loop/backing_file", "/dev/mmcblk0p5")
        _w(r, "/sys/fs/f2fs/loop0/lifetime_write_kbytes", "1024")
        _w(r, "/proc/sys/kernel/random/boot_id", "boot-1")

    def nand(self):
        r = self.root
        _w(r, "/proc/mounts",
           "/dev/root /rom squashfs ro 0 0\n"
           "ubi0:rootfs_data /overlay ubifs rw,noatime 0 0\n")
        _w(r, "/proc/diskstats", "")
        for k, v in {"max_ec": "150", "bad_peb_count": "1",
                     "reserved_for_bad": "20", "total_eraseblocks": "1000",
                     "eraseblock_size": "131072", "mtd_num": "5"}.items():
            _w(r, "/sys/class/ubi/ubi0/" + k, v)
        _w(r, "/sys/class/mtd/mtd5/type", "nand")
        _w(r, "/sys/class/mtd/mtd5/name", "ubi")


class TestParsers(unittest.TestCase):

    def test_diskstats_sectors_are_512_bytes(self):
        st = flash_wear.parse_diskstats(
            " 8 0 sda 1 0 2 3 4 0 10 5 0 0 0\n")
        self.assertEqual(st["sda"]["written"], 5120)
        self.assertEqual(st["sda"]["writes"], 4)

    def test_mount_escapes(self):
        m = flash_wear.parse_mounts("/dev/sda1 /mnt/my\\040disk ext4 rw 0 0")
        self.assertEqual(m[0]["mnt"], "/mnt/my disk")
        self.assertTrue(m[0]["rw"])

    def test_sources(self):
        self.assertEqual(flash_wear.source_of("ubi0:rootfs_data", "ubifs"),
                         {"kind": "ubi", "name": "ubi0"})
        self.assertEqual(flash_wear.source_of("/dev/mtdblock6", "jffs2"),
                         {"kind": "mtd", "name": "mtd6"})
        self.assertEqual(flash_wear.source_of("/dev/sda1", "ext4"),
                         {"kind": "block", "name": "sda1"})
        self.assertEqual(flash_wear.source_of("/dev/ubiblock0_0", "squashfs"),
                         {})
        self.assertEqual(flash_wear.disk_of("mmcblk0p5"), "mmcblk0")
        self.assertEqual(flash_wear.disk_of("nvme0n1p2"), "nvme0n1")

    def test_emmc_scale(self):
        w = flash_wear.emmc_wear("0x01 0x03", "0x01")
        self.assertEqual(w["type_a"], {"min": 0, "max": 10, "exceeded": False})
        self.assertEqual(w["percent_range"], [20, 30])
        self.assertEqual(w["level"], "ok")
        self.assertEqual(flash_wear.emmc_wear("0x0b 0x0b", "0x03")["level"],
                         "bad")
        self.assertEqual(flash_wear.emmc_wear("0x01 0x01", "0x02")["level"],
                         "warn")
        self.assertEqual(flash_wear.emmc_wear("", ""), {})
        self.assertEqual(flash_wear.emmc_wear("0x00 0x00", "0x00"), {})

    def test_ubi_is_an_estimate(self):
        w = flash_wear.ubi_wear("1500", "0", "20", 100000)
        self.assertEqual(w["percent"], 1.5)
        self.assertFalse(w["exact"])
        # Плохих блоков столько же, сколько резерва, — плохо при любом EC.
        self.assertEqual(flash_wear.ubi_wear("10", "20", "20", 100000)["level"],
                         "bad")

    def test_smart(self):
        nvme = "Percentage Used:                    7%\n" \
               "Data Units Written:                 1,000 [512 MB]\n"
        self.assertEqual(flash_wear.parse_smart(nvme)["percent"], 7)
        sata = ("ID# ATTRIBUTE_NAME FLAG VALUE WORST THRESH TYPE UPDATED "
                "WHEN_FAILED RAW_VALUE\n"
                "177 Wear_Leveling_Count 0x0013 095 095 000 Pre-fail "
                "Always - 50\n")
        self.assertEqual(flash_wear.parse_smart(sata)["percent"], 5)
        self.assertEqual(flash_wear.parse_smart("nothing"), {})

    def test_proc_io(self):
        self.assertEqual(flash_wear.parse_proc_io(
            "write_bytes: 4096\ncancelled_write_bytes: 1024\n"), 3072)
        self.assertEqual(flash_wear.parse_proc_io("rchar: 1\n"), -1)


class TestAccounting(unittest.TestCase):

    def test_deltas_go_to_the_day(self):
        t = time.mktime((2026, 10, 28, 12, 0, 0, 0, 0, -1))
        st = flash_wear.account({}, {"mmcblk0": 1000}, "b1", t)
        st = flash_wear.account(st, {"mmcblk0": 1500}, "b1", t + 60)
        self.assertEqual(st["days"]["2026-10-28"]["mmcblk0"], 1500)

    def test_reboot_starts_from_zero(self):
        t = time.mktime((2026, 10, 28, 12, 0, 0, 0, 0, -1))
        st = flash_wear.account({}, {"d": 10000}, "b1", t)
        # После перезагрузки ядро считает заново: 300 — это новая запись,
        # а не «минус 9700».
        st = flash_wear.account(st, {"d": 300}, "b2", t + 120)
        self.assertEqual(st["days"]["2026-10-28"]["d"], 10300)
        # И уменьшившийся счётчик в той же загрузке (переполнение) — так же.
        st = flash_wear.account(st, {"d": 100}, "b2", t + 180)
        self.assertEqual(st["days"]["2026-10-28"]["d"], 10400)

    def test_summary_today_month(self):
        now = time.mktime((2026, 10, 28, 12, 0, 0, 0, 0, -1))
        days = {"2026-10-28": {"a": 5, "b": 100}, "2026-10-27": {"a": 7},
                "2026-10-01": {"a": 1}, "2026-09-30": {"a": 1000}}
        s = flash_wear.summarize(days, ["a"], now)
        self.assertEqual(s["today"], 5)
        self.assertEqual(s["yesterday"], 7)
        self.assertEqual(s["month"], 13)
        self.assertEqual(s["prev_month"], 1000)
        self.assertEqual(len(s["series"]), 30)
        self.assertEqual(s["series"][-1], {"day": "2026-10-28", "bytes": 5})

    def test_old_days_are_dropped(self):
        st = {"days": {"2020-01-%02d" % i: {"a": 1} for i in range(1, 30)}}
        old = flash_wear.KEEP_DAYS
        flash_wear.KEEP_DAYS = 10
        try:
            st = flash_wear.account(st, {"a": 1}, "b", time.time())
        finally:
            flash_wear.KEEP_DAYS = old
        self.assertEqual(len(st["days"]), 10)


class TestDiscover(_Root):

    def test_flint2_emmc_through_loop_overlay(self):
        self.flint2()
        devs = flash_wear.discover(self.root, smart=False)
        self.assertEqual([d["id"] for d in devs], ["mmcblk0"])
        d = devs[0]
        self.assertEqual(d["kind"], "emmc")
        self.assertEqual(d["model"], "8GTF4R")
        self.assertEqual(d["wear"]["percent_range"], [20, 30])
        self.assertTrue(d["writes_supported"])
        self.assertEqual(d["mounts"][0]["mnt"], "/overlay")
        self.assertEqual(d["mounts"][0]["lifetime_written"], 1024 * 1024)
        self.assertEqual(flash_wear.counters(self.root, devs),
                         {"mmcblk0": 8192 * 512})

    def test_nand_has_wear_estimate_but_no_counter(self):
        self.nand()
        with mock.patch.object(flash_wear, "_endurance", return_value=100000):
            devs = flash_wear.discover(self.root, smart=False)
        d = devs[0]
        self.assertEqual((d["id"], d["kind"]), ("ubi0", "ubi"))
        self.assertEqual(d["wear"]["max_ec"], 150)
        self.assertFalse(d["writes_supported"])
        self.assertEqual(flash_wear.counters(self.root, devs), {})

    def test_sd_card_says_wear_unknown(self):
        self.flint2(life="", pre_eol="")
        _w(self.root, "/sys/devices/mmc/mmcblk0/device/type", "SD")
        d = flash_wear.discover(self.root, smart=False)[0]
        self.assertEqual(d["kind"], "sd")
        self.assertEqual(d["wear"]["source"], "none")

    def test_top_writers(self):
        _w(self.root, "/proc/42/io", "write_bytes: 8192\n")
        _w(self.root, "/proc/42/comm", "sing-box\n")
        _w(self.root, "/proc/43/io", "write_bytes: 0\n")
        top = flash_wear.top_writers(self.root)
        self.assertTrue(top["supported"])
        self.assertEqual([p["comm"] for p in top["items"]], ["sing-box"])


class TestFlashStats(_Root):

    def make(self):
        self.flint2()
        ram = os.path.join(self.root, "ram.json")
        disk = os.path.join(self.root, "disk.json")
        return flash_wear.FlashStats(root=self.root, ram_path=ram,
                                     disk_path=disk), ram, disk

    def test_sample_writes_ram_not_flash(self):
        fs, ram, disk = self.make()
        with mock.patch.object(fs, "_conf",
                               side_effect=lambda k, d: {"stats_flush_hours": 6}.get(k, d)):
            fs.sample()
        self.assertTrue(os.path.exists(ram))
        self.assertFalse(os.path.exists(disk))

    def test_stop_flushes_to_flash_unless_disabled(self):
        fs, ram, disk = self.make()
        with mock.patch.object(fs, "_conf", side_effect=lambda k, d: 0
                               if k == "stats_flush_hours" else d):
            fs.sample()
            fs.stop()
        self.assertFalse(os.path.exists(disk))
        with mock.patch.object(fs, "_conf", side_effect=lambda k, d: 6
                               if k == "stats_flush_hours" else d):
            fs.stop()
        self.assertTrue(os.path.exists(disk))

    def test_gui_restart_continues_from_ram_copy(self):
        fs, ram, disk = self.make()
        fs.sample()
        _w(self.root, "/proc/diskstats",
           " 179 0 mmcblk0 100 0 2000 10 50 0 9192 20 0 0 0\n")
        again = flash_wear.FlashStats(root=self.root, ram_path=ram,
                                      disk_path=disk)
        st = again.sample()
        today = flash_wear.day_key(time.time())
        # 8192 секторов с загрузки + 1000 после перезапуска GUI.
        self.assertEqual(st["days"][today]["mmcblk0"], 9192 * 512)

    def test_report_shape(self):
        fs, _, _ = self.make()
        r = fs.report(fresh=True)
        self.assertTrue(r["ok"])
        self.assertEqual(r["devices"][0]["writes"]["today"], 8192 * 512)
        self.assertEqual(r["total"]["today"], 8192 * 512)


class TestSaver(unittest.TestCase):

    def test_normalize_bounds(self):
        v, err = flash_saver.normalize({"writeback_sec": 5,
                                        "noatime": 1, "junk": 1,
                                        "ext4_commit_sec": 2,
                                        "persist_min_level": "error"})
        self.assertTrue(err)                         # writeback_sec < 30
        self.assertEqual(v["noatime"], True)
        self.assertEqual(v["ext4_commit_sec"], 5)
        self.assertEqual(v["persist_min_level"], "ERROR")
        self.assertNotIn("junk", v)

    def test_presets_only_use_known_fields(self):
        for p in flash_saver.PRESETS.values():
            v, err = flash_saver.normalize(p["values"])
            self.assertEqual(err, [])
            self.assertEqual(set(v), set(p["values"]))

    def test_writeback_values(self):
        self.assertEqual(flash_saver.writeback_values(60),
                         {"dirty_expire_centisecs": 6000,
                          "dirty_writeback_centisecs": 1500})
        self.assertEqual(flash_saver.writeback_values(30)
                         ["dirty_writeback_centisecs"], 750)

    def test_remount_plan_reverts_only_own_changes(self):
        mounts = flash_wear.parse_mounts(
            "/dev/sda1 /opt ext4 rw,relatime 0 0\n"
            "/dev/sdb1 /mnt ext4 rw,noatime 0 0\n")
        pers = {"/opt", "/mnt"}
        self.assertEqual(flash_saver.remount_plan(mounts, pers, True, 120, {}),
                         [("/opt", "noatime,commit=120"),
                          ("/mnt", "commit=120")])
        # Выключили: /opt меняли мы — вернуть; noatime у /mnt — из fstab.
        mounts = flash_wear.parse_mounts(
            "/dev/sda1 /opt ext4 rw,noatime,commit=120 0 0\n"
            "/dev/sdb1 /mnt ext4 rw,noatime 0 0\n")
        plan = flash_saver.remount_plan(
            mounts, pers, False, 0, {"noatime": ["/opt"], "commit": ["/opt"]})
        self.assertEqual(plan, [("/opt", "relatime,commit=5")])

    def test_ram_log_dir_descriptor(self):
        class P:
            log_dir = flash_saver.RamLogDir("/opt/var/log")
        with mock.patch.object(flash_saver, "_conf", return_value=False):
            self.assertEqual(P().log_dir, "/opt/var/log")
        with mock.patch.object(flash_saver, "_conf", return_value=True), \
                mock.patch.object(flash_saver, "is_ram_path",
                                  return_value=False), \
                mock.patch("os.makedirs"):
            self.assertEqual(P().log_dir, flash_saver.RAM_LOG_DIR)
        # Каталог и так в ОЗУ — не трогаем.
        with mock.patch.object(flash_saver, "_conf", return_value=True), \
                mock.patch.object(flash_saver, "is_ram_path",
                                  return_value=True):
            self.assertEqual(P().log_dir, "/opt/var/log")

    def test_keenetic_platforms_use_descriptor(self):
        from core.awg_platform import KeeneticPlatform
        from core.mihomo_platform import KeeneticMihomo
        from core.singbox_platform import KeeneticSingbox
        for cls in (KeeneticPlatform, KeeneticMihomo, KeeneticSingbox):
            self.assertIsInstance(cls.__dict__["log_dir"],
                                  flash_saver.RamLogDir)

    def test_mount_of_and_ram(self):
        mounts = flash_wear.parse_mounts(
            "/dev/sda1 / ext4 rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n")
        self.assertEqual(flash_saver.mount_of("/tmp/x", mounts)["mnt"], "/tmp")
        self.assertEqual(flash_saver.mount_of("/tmpx", mounts)["mnt"], "/")
        self.assertTrue(flash_saver.is_ram_path("/tmp/zapret-gui", mounts))

    def test_swaps(self):
        self.assertEqual(flash_saver.parse_swaps(
            "Filename Type Size Used Priority\n/dev/sda2 partition 1 0 -2\n"),
            [{"name": "/dev/sda2", "type": "partition"}])


class TestProxyTrafficThrottle(unittest.TestCase):

    def test_saves_are_throttled_and_flushed(self):
        from core import proxy_traffic as pt
        tmp = tempfile.mkdtemp(prefix="pt-flash-")
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "pt.json")
        polls = iter([[{"id": "a", "upload": 1, "download": 1,
                        "chains": ["X"]}],
                      [{"id": "a", "upload": 5, "download": 1,
                        "chains": ["X"]}]])
        tr = pt.TrafficTracker(
            targets_fn=lambda: [{"host": "127.0.0.1", "port": 1}],
            state_path_fn=lambda: path)
        with mock.patch.object(pt, "_clash_get", side_effect=lambda *a, **k: (
                200, __import__("json").dumps({"connections": next(polls)}))), \
                mock.patch.object(flash_saver, "counters_flush_sec",
                                  return_value=3600):
            tr._poll_all()                  # первый раз — сразу
            first = os.path.getmtime(path)
            os.utime(path, (first - 100, first - 100))
            tr._poll_all()                  # второй — отложен
            self.assertEqual(os.path.getmtime(path), first - 100)
            tr.flush()
        self.assertGreater(os.path.getmtime(path), first - 100)


class TestAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from tests._wsgi_client import WSGIClient, build_test_app
        cls.client = WSGIClient(build_test_app())

    def setUp(self):
        from core.config_manager import get_config_manager
        cm = get_config_manager()
        saved = {s: dict(cm.get(s, default={}) or {})
                 for s in ("flash", "logging", "history")}
        self.addCleanup(lambda: [cm.set(s, v) for s, v in saved.items()])
        tmp = tempfile.mkdtemp(prefix="flash-api-")
        self.addCleanup(shutil.rmtree, tmp, True)
        fs = flash_wear.FlashStats(ram_path=os.path.join(tmp, "r.json"),
                                   disk_path=os.path.join(tmp, "d.json"))
        p = mock.patch.object(flash_wear, "get_flash_stats", return_value=fs)
        p.start()
        self.addCleanup(p.stop)
        p2 = mock.patch.object(flash_saver, "apply",
                               return_value={"ok": True, "applied": [],
                                             "errors": []})
        p2.start()
        self.addCleanup(p2.stop)
        p3 = mock.patch.object(get_config_manager(), "save", return_value=True)
        p3.start()
        self.addCleanup(p3.stop)

    def test_status_has_everything(self):
        code, _, body = self.client.request("GET", "/api/flash/status")
        self.assertEqual(code, 200)
        for k in ("devices", "settings", "presets", "state", "hints",
                  "top_writers"):
            self.assertIn(k, body)

    def test_settings_save_and_validate(self):
        code, _, body = self.client.request(
            "PUT", "/api/flash/settings",
            body={"engine_logs_ram": True, "persist_critical": False})
        self.assertEqual(code, 200, body)
        self.assertTrue(body["settings"]["engine_logs_ram"])
        from core.config_manager import get_config_manager
        self.assertFalse(get_config_manager().get("logging",
                                                  "persist_critical"))
        code, _, _ = self.client.request(
            "PUT", "/api/flash/settings", body={"writeback_sec": "много"})
        self.assertEqual(code, 400)

    def test_unknown_action(self):
        code, _, _ = self.client.request("POST", "/api/flash/action",
                                         body={"name": "rm -rf"})
        self.assertEqual(code, 400)


if __name__ == "__main__":
    unittest.main()
