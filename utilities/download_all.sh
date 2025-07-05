mkdir -p bundle_store/
python3 cwe2stix.py --version 4.5 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_5.json && \
python3 cwe2stix.py --version 4.6 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_6.json && \
python3 cwe2stix.py --version 4.7 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_7.json && \
python3 cwe2stix.py --version 4.8 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_8.json && \
python3 cwe2stix.py --version 4.9 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_9.json && \
python3 cwe2stix.py --version 4.10 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_10.json && \
python3 cwe2stix.py --version 4.11 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_11.json && \
python3 cwe2stix.py --version 4.12 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_12.json && \
python3 cwe2stix.py --version 4.13 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_13.json && \
python3 cwe2stix.py --version 4.14 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_14.json && \
python3 cwe2stix.py --version 4.15 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_15.json && \
python3 cwe2stix.py --version 4.16 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_16.json && \
python3 cwe2stix.py --version 4.17 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_17.json