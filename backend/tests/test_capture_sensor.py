import os
import sys
import pytest
from scripts.capture import command, capture


def test_sensor_interface_validation():
    with pytest.raises(ValueError):
        command("nonexistent-lab-interface",10)


def test_sensor_argument_array(monkeypatch):
    monkeypatch.setattr("scripts.capture.socket.if_nameindex",lambda:[(1,"vpn0")])
    args=command("vpn0",100)
    assert isinstance(args,list) and args[args.index("-w")+1]=="-"
    assert args[args.index("-c")+1]=="100"


def test_sensor_refuses_existing_symlink(tmp_path,monkeypatch):
    monkeypatch.setattr("scripts.capture.command",lambda *args:[])
    target=tmp_path/"target"
    target.write_text("untouched")
    link=tmp_path/"link"
    link.symlink_to(target)
    with pytest.raises(FileExistsError):
        capture("vpn0",link)
    assert target.read_text()=="untouched"


def test_sensor_stream_bound_cleanup(tmp_path,monkeypatch):
    monkeypatch.setattr("scripts.capture.command",lambda *args:[sys.executable,"-c","import sys; sys.stdout.buffer.write(bytes(100))"])
    target=tmp_path/"bounded.pcap"
    with pytest.raises(ValueError,match="ceiling"):
        capture("vpn0",target,duration=1,max_bytes=24)
    assert not target.exists()


def test_sensor_exclusive_private_output(tmp_path,monkeypatch):
    monkeypatch.setattr("scripts.capture.command",lambda *args:[sys.executable,"-c","import sys; sys.stdout.buffer.write(bytes(24))"])
    target=tmp_path/"capture.pcap"
    assert capture("vpn0",target,duration=1)==24
    assert os.stat(target).st_mode & 0o777==0o600
