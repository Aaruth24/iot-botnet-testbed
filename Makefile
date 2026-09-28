.PHONY: help setup up down run logs status dashboard clean fix-perms test-ids results

help:
	@echo "-> showing available commands"
	@echo "Available commands: setup up down run logs status dashboard clean fix-perms test-ids results"
setup:
	@echo "-> checking Linux and Docker setup"
	@bash scripts/setup.sh
up:
	@echo "-> starting the Linux Docker stack"
	@docker compose up --build -d && echo "Dashboard: http://localhost:5000"
down:
	@echo "-> stopping containers and removing volumes"
	@docker compose down -v
run:
	@echo "-> running the full experiment"
	@bash scripts/run_experiment.sh
logs:
	@echo "-> following service logs"
	@docker compose logs -f
status:
	@echo "-> showing service status"
	@docker compose ps
dashboard:
	@echo "-> opening the dashboard"
	@xdg-open http://localhost:5000 || echo "Open http://localhost:5000"
clean:
	@echo "-> cleaning containers, volumes, and generated data"
	@bash scripts/cleanup.sh
fix-perms:
	@echo "-> fixing shell script permissions"
	@chmod +x scripts/*.sh mininet/entrypoint.sh botnet/entrypoint.sh
test-ids:
	@echo "-> evaluating the IDS"
	@docker compose exec ids python /app/ids/evaluate.py
results:
	@echo "-> displaying metrics"
	@cat data/results/metrics.json | python3 -m json.tool
