from setuptools import setup
from pathlib import Path

long_description = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="IR_Sim",
    version="2.0.0",
    author="errmorra",
    description="MITRE ATT&CK-mapped Incident Response Tabletop Simulator — 20 scenarios, GRC report export",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/errmorra/IR_Sim",
    py_modules=["app"],
    python_requires=">=3.9",
    extras_require={"modern-ui": ["customtkinter>=5.2.0"]},
    entry_points={"console_scripts": ["ir_sim=app:main"]},
    package_data={"": ["scenarios.json"]},
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Education",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "Development Status :: 5 - Production/Stable",
    ],
    keywords=[
        "cybersecurity", "incident-response", "MITRE-ATTACK", "GRC",
        "tabletop", "NIST", "HIPAA", "compliance", "simulation", "training"
    ],
)
