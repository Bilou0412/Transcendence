# Variables
COMPOSE = docker compose
SERVICE_DIRS := $(wildcard *-service)
NETWORK = my_network
REDIS = redis

# Colors
GREEN = \033[0;32m
RED = \033[0;31m
NC = \033[0m

# Phony targets
.PHONY: help up down logs clean create-network logs-terminator

help:
	@echo "$(GREEN)Available commands:$(NC)"
	@echo " make up             - Start all services"
	@echo " make down           - Stop all services"
	@echo " make logs           - View logs"
	@echo " make logs-terminator - View logs in Terminator (one pane per service)"
	@echo " make clean          - Remove containers and volumes"

create-network:
	@if ! docker network ls --format '{{.Name}}' | grep -q "^$(NETWORK)$$"; then \
		echo "$(GREEN)Creating network $(NETWORK)...$(NC)"; \
		docker network create $(NETWORK); \
	fi

create-redis:
	@if ! docker ps --format '{{.Names}}' | grep -q "^redis$$"; then \
		echo "$(GREEN)Starting Redis service...$(NC)"; \
		docker run -d --name redis --network my_network -p 6380:6379 redis:latest; \
	fi

up: create-network create-redis
	@echo "$(GREEN)Starting services...$(NC)"
	@$(foreach dir, $(SERVICE_DIRS), \
		(echo "Starting $(dir)"; cd $(dir) && $(COMPOSE) up --build -d) &&) true

down:
	@echo "$(GREEN)Stopping services...$(NC)"
	@$(foreach dir, $(SERVICE_DIRS), \
		(echo "Stopping $(dir)"; cd $(dir) && $(COMPOSE) down) &&) true
	@if docker ps --format '{{.Names}}' | grep -q "^redis$$"; then \
        echo "$(GREEN)Stopping Redis service...$(NC)"; \
        docker stop redis; \
		docker rm redis; \
    fi

logs:
	@echo "$(GREEN)Opening GNOME Terminal with tabs for all services...$(NC)"
	@$(foreach dir, $(SERVICE_DIRS), \
		(gnome-terminal -- bash -c "cd $(dir) && docker compose logs -f; exec bash" &) &&) true


clean:
	@echo "$(RED)Cleaning up...$(NC)"
	@$(foreach dir, $(SERVICE_DIRS), \
        (echo "Cleaning $(dir)"; cd $(dir) && $(COMPOSE) down -v --remove-orphans || true) &&) true
	@if docker network inspect $(NETWORK) >/dev/null 2>&1; then \
		echo "$(RED)Checking for containers connected to $(NETWORK)...$(NC)"; \
		CONTAINERS=$$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' $(NETWORK)); \
		if [ -n "$$CONTAINERS" ]; then \
			echo "$(RED)Force disconnecting containers from $(NETWORK)...$(NC)"; \
			for container in $$CONTAINERS; do \
				docker network disconnect -f $(NETWORK) $$container; \
			done; \
		fi; \
		echo "$(RED)Removing network $(NETWORK)...$(NC)"; \
		docker network rm $(NETWORK); \
	fi
	@if [ -d "media-service/images/users_images/" ]; then \
    echo "$(RED)Removing media-service/images/users_images/ folder...$(NC)"; \
    rm -rf media-service/images/users_images/; \
    fi
	@echo "$(RED)Pruning unused volumes...$(NC)"
	@docker volume prune -f

