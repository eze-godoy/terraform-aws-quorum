## Architecture

```mermaid
flowchart TD
    GHA[GitHub Actions] -->|OIDC| IAM[AWS IAM]

    IAM --> Bedrock[Bedrock<br/>AI Models]
    IAM --> DynamoDB[DynamoDB<br/>Metrics]
    IAM --> S3[S3<br/>Raw Outputs]

    Bedrock --> CloudWatch[CloudWatch<br/>Logs/Alarms]
    DynamoDB --> CloudWatch
    S3 --> CloudWatch
```

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our development process and how to submit pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Ezequiel Godoy** - [GitHub](https://github.com/eze-godoy) | [LinkedIn](https://www.linkedin.com/in/ezegodoy/)

---

Part of the [Quorum](https://github.com/eze-godoy/quorum-action) project - Multi-Model AI Code Review with Consensus Filtering.
