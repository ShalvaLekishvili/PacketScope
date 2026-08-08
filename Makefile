.PHONY: install run test lint demo report slice docker clean

install:
	python -m pip install -e ".[dev]"

run:
	packetscope serve --host 127.0.0.1 --port 8000

test:
	pytest -q

lint:
	ruff check packetscope tests scripts

demo:
	python scripts/generate_demo_pcap.py
	packetscope analyze sample-data/demo-beacon.pcap

report:
	packetscope analyze sample-data/demo-beacon.pcap --report demo-report.html

slice:
	packetscope slice sample-data/demo-beacon.pcap demo-slice.pcapng --packets 1,2,3

docker:
	docker compose up --build

clean:
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info demo-report.html demo-slice.pcapng
