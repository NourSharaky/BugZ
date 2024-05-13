
![Logo](https://github.com/NourSharaky/BugZ/blob/811c441a7afec84da8ddbbd2b1a6407d15fda51d/app/static/images/logo.png)


# BugZ SAST: Elevating Secure Software Development

BugZ is a state-of-the-art Static Application Security Testing (SAST) tool designed to help developers identify and remediate security vulnerabilities in their codebases. With the increasing complexity of software development and the ever-evolving threat landscape, ensuring the security of dependencies and code is paramount. 



## Objective
The primary goal of BugZ is to empower developers and security teams with a tool that is both efficient and intuitive, making security an integral part of the development process without adding undue burden. BugZ is built to cater to the needs of modern development environments, offering seamless integrations, comprehensive reporting, and a user-friendly interface.

## Run Locally

Clone the project

```bash
  git clone https://github.com/NourSharaky/BugZ.git
```

Go to the project directory

```bash
  cd BugZ/app/
```

Install dependencies

```bash
    pip install -r requirements.txt
```

Start BugZ

```bash
  python app.py
```


## Scanning Capabilities

- **Dependency Scan**: Evaluates third-party libraries and frameworks integrated into your application to identify known security vulnerabilities.
- **Code Scan**: Analyzes your source code to detect security flaws and risky coding practices that could lead to security breaches.
- **Full Scan**: Combines the power of Dependency and Code Scans to provide a thorough assessment of your entire application for maximum security coverage.
- **AI Integration**: At the core of BugZ is its innovative use of OpenAI's GPT-3.5 Turbo, which enhances the tool's ability to not only detect issues but also to provide accurate and context-aware technical recommendations. This AI-driven approach ensures that BugZ not only flags issues but also assists developers in understanding the implications of detected vulnerabilities and offers viable remediation strategies. This integration aims to reduce the manual overhead typically associated with vulnerability management and to accelerate the secure development lifecycle.


## Documentation

[Documentation](https://bugz-documentation.vercel.app/)


## Authors

- [@NourSharaky](https://github.com/NourSharaky)
