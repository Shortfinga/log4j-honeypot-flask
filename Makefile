# Makefile mainly for running code quality suff
PROJECTFOLDER := app
PIPENV := pipenv
BLACK := $(PIPENV) run python -m black
ISORT := $(PIPENV) run python -m isort
MYPY := $(PIPENV) run python -m mypy
PYLINT := $(PIPENV) run python -m pylint
PYTEST := $(PIPENV) run py.test

test: black isort mypy pylint doctest

mypy:
	${MYPY} ${PROJECTFOLDER} \
	    --disallow-untyped-calls \
	    --disallow-untyped-defs \
	    --disallow-incomplete-defs \
	    --check-untyped-defs

black:
	${BLACK} --check ${PROJECTFOLDER}/

isort:
	${ISORT} --check ${PROJECTFOLDER}/

format:
	${BLACK} ${PROJECTFOLDER}/
	${ISORT} ${PROJECTFOLDER}/

pylint:
	${PYLINT} ${PROJECTFOLDER}/

doctest:
	${PYTEST} --doctest-modules ${PROJECTFOLDER}
