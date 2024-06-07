# Stytch: B2B Magic Links Example

This repository contains a sample application demonstrating a B2B Magic Links
flow using a Go backend.

## Running Locally

### Prerequisites

- Go `^v1.22`.
- A Stytch account.
    - A test project.
    - The project id and project secret for your test project.

### Quickstart

#### 1. Clone the repo.

```shell
git clone git@github.com:stytchauth/stytch-go-b2b-magic-links.git
```

#### 2. Install dependencies.

```shell
go get
```

#### 3. Populate environment variables.

```shell
cp .env.template .env.local
```

Populate the `STYTCH_PROJECT_ID` and `STYTCH_SECRET` in the new `.env.local` file.

#### 4. Run the application.

```shell
go run ./...
```

The service will be available at [http://localhost:3000/](http://localhost:3000/).
