#!/bin/bash

# =============================================================================
# LegacyKeep Auth Service - Database Setup Script
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    print_success "Docker is running"
}

# Function to start the database services
start_services() {
    print_status "Starting PostgreSQL and Redis services..."
    
    if [ -f docker-compose.yml ]; then
        docker compose up -d
        print_success "Services started successfully!"
    else
        print_error "docker-compose.yml not found!"
        exit 1
    fi
}

# Function to stop the database services
stop_services() {
    print_status "Stopping PostgreSQL and Redis services..."
    docker compose down
    print_success "Services stopped successfully!"
}

# Function to restart the database services
restart_services() {
    print_status "Restarting PostgreSQL and Redis services..."
    docker compose restart
    print_success "Services restarted successfully!"
}

# Function to check service health
check_health() {
    print_status "Checking service health..."
    
    # Check PostgreSQL
    if docker compose exec -T postgres pg_isready -U postgres -d auth_db > /dev/null 2>&1; then
        print_success "PostgreSQL is healthy"
    else
        print_warning "PostgreSQL is not ready yet"
    fi
    
    # Check Redis
    if docker compose exec -T redis redis-cli ping > /dev/null 2>&1; then
        print_success "Redis is healthy"
    else
        print_warning "Redis is not ready yet"
    fi
}

# Function to show service status
show_status() {
    print_status "Service status:"
    docker compose ps
}

# Function to show logs
show_logs() {
    print_status "Showing service logs..."
    docker compose logs -f
}

# Function to reset database (WARNING: This will delete all data)
reset_database() {
    print_warning "This will delete all database data. Are you sure? (y/N)"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        print_status "Resetting database..."
        docker compose down -v
        docker compose up -d
        print_success "Database reset successfully!"
    else
        print_status "Database reset cancelled"
    fi
}

# Function to show connection details
show_connection_details() {
    echo ""
    print_status "Connection Details:"
    echo "=================================="
    echo "PostgreSQL:"
    echo "  Host: localhost"
    echo "  Port: 5432"
    echo "  Database: auth_db"
    echo "  Username: postgres"
    echo "  Password: password"
    echo ""
    echo "Redis:"
    echo "  Host: localhost"
    echo "  Port: 6379"
    echo "  Password: (none)"
    echo ""
    echo "pgAdmin (Database Management):"
    echo "  URL: http://localhost:5050"
    echo "  Email: admin@legacykeep.com"
    echo "  Password: admin123"
    echo "=================================="
}

# Function to show help
show_help() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start     Start PostgreSQL and Redis services"
    echo "  stop      Stop PostgreSQL and Redis services"
    echo "  restart   Restart PostgreSQL and Redis services"
    echo "  status    Show service status"
    echo "  health    Check service health"
    echo "  logs      Show service logs"
    echo "  reset     Reset database (WARNING: deletes all data)"
    echo "  info      Show connection details"
    echo "  help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start    # Start services"
    echo "  $0 status   # Check status"
    echo "  $0 info     # Show connection details"
}

# Main script logic
case "${1:-help}" in
    start)
        check_docker
        start_services
        sleep 5
        check_health
        show_connection_details
        ;;
    stop)
        stop_services
        ;;
    restart)
        check_docker
        restart_services
        sleep 5
        check_health
        ;;
    status)
        show_status
        ;;
    health)
        check_health
        ;;
    logs)
        show_logs
        ;;
    reset)
        check_docker
        reset_database
        ;;
    info)
        show_connection_details
        ;;
    help|*)
        show_help
        ;;
esac
