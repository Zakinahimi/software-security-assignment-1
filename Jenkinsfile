// CI/CD gate for the Research Workspace assignment.
//
// Implements the "Implementation & build" / "Testing" gates from docs/SSDLC_PLAN.md:
//   1. Build/validate each component, run static analysis and dependency analysis.
//   2. Start a fresh test environment (docker-compose) and run the functional and
//      authorization/security test suite against it.
//   3. Archive test and analysis results as Jenkins artifacts.
// The build is configured to FAIL on: any failing test, any pip-audit finding of severity
// medium-or-above on a direct dependency, and any supply-chain integrity-manifest mismatch for
// the benign exportkit build (a mismatch there means the approved artifact itself is broken,
// not — as with the malicious fixture — a working security gate).

pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    environment {
        RESEARCH_WORKSPACE_JWT_SECRET = 'dev-only-shared-secret-change-me-32bytes!!'
    }

    stages {

        stage('Build & install') {
            steps {
                sh '''
                    set -eu
                    python3 -m venv .venv
                    . .venv/bin/activate
                    pip install --upgrade pip
                    pip install -r requirements-dev.txt
                    pip install packages/exportkit
                    for svc in resource-service application-api processing-service; do
                        pip install -r services/$svc/requirements.txt
                    done
                '''
            }
        }

        stage('Static analysis') {
            steps {
                sh '''
                    set -eu
                    . .venv/bin/activate
                    mkdir -p reports
                    ruff check services packages scripts tests --output-format=junit --output-file=reports/ruff.xml || true
                    ruff check services packages scripts tests
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/ruff.xml'
                }
            }
        }

        stage('Dependency analysis') {
            steps {
                sh '''
                    set -eu
                    . .venv/bin/activate
                    mkdir -p reports
                    for svc in resource-service application-api processing-service; do
                        pip-audit -r services/$svc/requirements.txt \
                            --format json --output reports/pip-audit-$svc.json \
                            --strict --desc on || PIP_AUDIT_FAILED=1
                    done
                    if [ "${PIP_AUDIT_FAILED:-0}" = "1" ]; then
                        echo "pip-audit reported a finding at or above the configured severity — failing the gate."
                        exit 1
                    fi
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/pip-audit-*.json', allowEmptyArchive: true
                }
            }
        }

        stage('Supply-chain integrity gate') {
            steps {
                sh '''
                    set -eu
                    . .venv/bin/activate
                    echo "--- benign exportkit (must be APPROVED) ---"
                    python scripts/verify_manifest.py packages/exportkit/dist/*.whl
                    echo "--- malicious fixture (must be REJECTED - this is the control case) ---"
                    if python scripts/verify_manifest.py packages/exportkit-malicious/dist/*.whl; then
                        echo "ERROR: malicious fixture was approved — the integrity gate is broken."
                        exit 1
                    fi
                    echo "integrity gate behaved as expected."
                '''
            }
        }

        stage('Unit tests (per service)') {
            steps {
                sh '''
                    set -eu
                    . .venv/bin/activate
                    mkdir -p reports
                    for svc in resource-service application-api processing-service; do
                        (cd services/$svc && python -m pytest -q --junitxml=../../reports/unit-$svc.xml)
                    done
                '''
            }
            post {
                always {
                    junit testResults: 'reports/unit-*.xml'
                }
            }
        }

        stage('Fresh environment: functional + authorization e2e tests') {
            steps {
                sh '''
                    set -eu
                    mkdir -p reports
                    docker compose up --build -d resource-service processing-service application-api
                    docker compose --profile test build test-runner
                    docker compose --profile test run --rm test-runner
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/e2e-results.xml'
                    sh 'docker compose down -v || true'
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
        failure {
            echo 'Build failed — a required functional/security test, a dependency-audit finding, or the supply-chain gate rejected this build. Confirmed violations of the required security guarantees must be fixed before release, per docs/SSDLC_PLAN.md.'
        }
    }
}
