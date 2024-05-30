```markdown
# Short URL Generator

This project is a URL shortening service that uses Redis for storing URLs. The service includes logging of URL usage, and supports setting expiration dates and usage limits for each URL.

## Features

- URL shortening
- Setting expiration dates for URLs
- Setting usage limits for URLs
- Logging URL access details
- Moving expired or exhausted URLs to specific categories in Redis

## Prerequisites

- Go 1.16 or higher
- Redis

## Installation and Running

### Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/mdsatpak/short-url-generator.git
    cd short-url-generator
    ```

2. Install the project dependencies:

    ```sh
    go mod tidy
    ```

### Running

1. Start Redis (edit the `config.yaml` file if necessary):

    ```sh
    redis-server
    ```

2. Run the application:

    ```sh
    go run main.go
    ```

### Configuration File

Configuration values are stored in the `config.yaml` file:

```yaml
webserver:
  port: "8080"
  ip: "127.0.0.1"

redis:
  address: "localhost:6379"
  password: ""
  db: 0
```

## Usage

### API

#### 1. Shorten URL

- **Endpoint**: `/shorten`
- **Method**: `POST`
- **Request Body**:
  - `originalURL` (string): The original URL
  - `expiry` (string, optional): Expiration date in `RFC3339` format
  - `maxUsage` (string, optional): Maximum usage count

- **Response**:

  ```json
  {
    "originalURL": "http://example.com",
    "shortURL": "http://localhost:8080/abc123"
  }
  ```

- **Example**:

  ```sh
  curl -X POST -H "Content-Type: application/json" -d '{"originalURL":"http://example.com", "expiry":"2024-12-31T23:59:59Z", "maxUsage":"10"}' http://localhost:8080/shorten
  ```

#### 2. Redirect to Original URL

- **Endpoint**: `/{shortURL}`
- **Method**: `GET`
- **Response**: Redirects to the original URL

- **Example**:

  ```sh
  curl http://localhost:8080/abc123
  ```

## Development and Contribution

1. Fork the project.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
```

### Explanation of the `README.md` File

- **Features**: Describes the main features of the project.
- **Prerequisites**: Lists the required tools and software needed to run the project.
- **Installation and Running**: Provides instructions on how to install dependencies and run the project.
- **Configuration File**: Explains the configuration file and how to set it up.
- **Usage**: Documents the API, including endpoints, methods, request and response formats, and usage examples.
- **Development and Contribution**: Offers guidance on how to contribute to the project.
- **License**: Specifies the project's license type.

This file will help users and developers easily install, run, and use the project.