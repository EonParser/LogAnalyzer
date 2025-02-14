from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="log-analyzer",
    version="1.0.0",
    author="Sneh Patel",
    author_email="supatel5678.90@gmail.com",
    description="A robust log analysis tool with CLI and web interface",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/log-analyzer",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={
        "log_analyzer.web": ["static/*"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "fastapi>=0.68.0",
        "uvicorn>=0.15.0",
        "rich>=10.0.0",
        "python-multipart>=0.0.5",
        "pydantic>=1.8.0",
        "aiofiles>=0.7.0",
    ],
    entry_points={
        "console_scripts": [
            "loganalyzer=log_analyzer.cli:cli",
            "loganalyzer-web=log_analyzer.web.app:start",
        ],
    },
)