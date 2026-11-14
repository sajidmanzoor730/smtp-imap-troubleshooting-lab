.PHONY: test install demo
test:
	PYTHONPATH=src python3 -m unittest discover -s tests -t . -v

install:
	python3 -m pip install -e .

demo:
	PYTHONPATH=src python3 -m maillab mock smtp --mode starttls_unavailable --port 2525
