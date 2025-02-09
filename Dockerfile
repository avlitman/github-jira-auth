# Use an official Go runtime as a parent image
FROM golang:1.18 as builder

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to the working directory
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code to the working directory
COPY . .

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux go build -o github-proxy .

# Use a minimal base image to run the Go application
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /app/github-proxy .

# Expose the application port
EXPOSE 9900

# Command to run the executable
ENTRYPOINT ["./github-proxy"]
