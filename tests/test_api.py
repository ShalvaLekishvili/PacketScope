from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from packetscope.api import app
from packetscope.capture import iter_capture


client=TestClient(app)


def test_health_endpoint():
    response=client.get('/api/health')
    assert response.status_code==200
    assert response.json()['version']=='2.0.0'


def test_config_endpoint():
    response=client.get('/api/config')
    assert response.status_code==200
    assert 'detections' in response.json()


def test_analyze_rejects_extension():
    response=client.post('/api/analyze?filename=x.txt',content=b'no')
    assert response.status_code==415


def test_analyze_raw_capture_creates_session(demo_capture:Path):
    response=client.post('/api/analyze?filename=evidence.pcap',content=demo_capture.read_bytes(),headers={'Content-Type':'application/octet-stream'})
    assert response.status_code==200
    data=response.json()
    assert data['source_name']=='evidence.pcap'
    assert len(data['session_id'])==32
    client.delete(f"/api/sessions/{data['session_id']}")


def test_demo_annotation_slice_and_delete():
    response=client.get('/api/demo')
    assert response.status_code==200
    data=response.json(); session=data['session_id']; finding=data['findings'][0]
    annotation=client.patch(f"/api/sessions/{session}/findings/{finding['id']}",json={'status':'investigating','verdict':'suspicious','note':'validated','tags':['demo','network']})
    assert annotation.status_code==200
    assert annotation.json()['status']=='investigating'
    refreshed=client.get(f'/api/sessions/{session}').json()
    assert refreshed['findings'][0]['analyst']['note']=='validated'
    sliced=client.get(f"/api/sessions/{session}/findings/{finding['id']}/slice")
    assert sliced.status_code==200
    assert sliced.content[:4]==b'\x0a\x0d\x0d\x0a'
    report=client.get(f'/api/sessions/{session}/report')
    assert report.status_code==200 and 'PacketScope Report' in report.text
    assert client.delete(f'/api/sessions/{session}').status_code==204
    assert client.get(f'/api/sessions/{session}').status_code==404


def test_annotation_validation_rejects_bad_status():
    data=client.get('/api/demo').json(); session=data['session_id']; finding=data['findings'][0]['id']
    response=client.patch(f'/api/sessions/{session}/findings/{finding}',json={'status':'wat'})
    assert response.status_code==400
    client.delete(f'/api/sessions/{session}')
