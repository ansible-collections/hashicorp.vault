# Default files to check for syntax
CHECK_SYNTAX_FILES ?= plugins/ tests/

# Help target
help:
	@echo "Available targets:"
	@echo "  help             - Show this help message"
	@echo "  check_black      - Run black syntax check"
	@echo "  check_flake8     - Run flake8 syntax check"
	@echo "  check_isort      - Run isort syntax check"

# Run black syntax check
check_black:
	tox -e black -- --check $(CHECK_SYNTAX_FILES)

# Run flake8 syntax check
check_flake8:
	tox -e flake8 -- $(CHECK_SYNTAX_FILES)

# Run isort syntax check
check_isort:
	tox -e isort -- --check $(CHECK_SYNTAX_FILES)

# Example and Molecule pipeline
examples:
	python -m tools.generate_examples
	python -m tools.inject_examples

examples-check:
	python -m tools.inject_examples --check

molecule-scenarios:
	python -m tools.generate_molecule_scenarios

molecule-local:
	molecule test --all

molecule-real:
	molecule test --all -i extensions/molecule/inventory_real.yml

.PHONY: help check_black check_flake8 check_isort examples examples-check molecule-scenarios molecule-local molecule-real
