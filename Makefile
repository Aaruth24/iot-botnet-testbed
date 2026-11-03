.PHONY: up down build logs ps clean experiment attack stop reports help

help:
	@echo "IoT Security Testbed — make targets"
	@echo "  make up          build + start the whole testbed (dashboard on :8080)"
	@echo "  make down        stop and remove containers"
	@echo "  make build       (re)build all images"
	@echo "  make logs        follow logs from every service"
	@echo "  make ps          show running services"
	@echo "  make experiment  trigger the automated evaluation pipeline"
	@echo "  make attack      launch a port-scan attack for a quick demo"
	@echo "  make stop        stop attack traffic"
	@echo "  make reports     list generated result files in ./data"
	@echo "  make clean       down + remove images, volumes and ./data outputs"

up:
	docker compose up --build -d
	@echo ""
	@echo "Dashboard:  http://localhost:8080"

build:
	docker compose build

down:
	docker compose down

logs:
	docker compose logs -f --tail=80

ps:
	docker compose ps

experiment:
	docker compose exec redis redis-cli set control:run_experiment 1
	@echo "Experiment triggered — watch http://localhost:8080"

attack:
	docker compose exec redis redis-cli set control:attack \
	  '{"active":true,"type":"scan","intensity":3,"duration":30,"started":0}'
	@echo "Attack traffic launched for ~30s"

stop:
	docker compose exec redis redis-cli set control:attack '{"active":false}'

reports:
	@ls -la data/ 2>/dev/null || echo "no reports yet — run 'make experiment'"

clean:
	docker compose down -v --rmi local
	rm -f data/*.json data/*.csv data/*.joblib 2>/dev/null || true
