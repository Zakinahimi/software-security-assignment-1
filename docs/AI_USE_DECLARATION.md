# Declaration of use of Generative Artificial Intelligence (GAI)

Follows the structure of the Aarhus University "Declaration of use of GAI" form (version of
June 4th, 2025) and the university's guidelines (https://studerende.au.dk/en/gai).
Assignment: Software Security — Assignment I (Research Workspace).

- [x] **I/we used generative artificial intelligence (GAI) to complete this project.**

## GAI tool(s) used (with version)

- **Claude Code** (Anthropic's coding assistant, used in the terminal / VS Code), running the
  **Claude Sonnet 5** model during implementation and **Claude Sonnet 5.5**
  (`claude-sonnet-5-5`) during the final review described under "Final consistency review" below.

No other GAI tool was used for this assignment.

## How GAI was used

Ticked use cases from the form's list:

| Use case (from the form) | Used? |
|---|---|
| For inspiration in formulating a thesis statement | No |
| For inspiration in relation to choice of theory and method | No |
| For feedback on own text | **Yes** (grammar/language only) |
| For alternative ways of formulating text | **Yes** (grammar/language only) |
| To get started on my/our writing | No |
| To understand a topic better | No |
| To aid me in my reading process | No |
| I/we write about the topic of GAI in the project | No |
| To find gaps in our knowledge | No |
| To get started on my/our search for information | **Yes** (finding sources) |
| For programming tasks | **Yes** (writing code) |
| For data analysis | No |
| To create diagrams | No |
| Other use case(s) | **Yes** (final consistency review, see below) |

### What the authors did themselves (without GAI)

The authors wrote the report, and produced the architecture, the threat model (STRIDE), the
access-control matrix, the secure-development plan / idea planning, the choice of system and
component boundaries, the choice of which vulnerabilities to plant, and the authorization and
token design. These are the authors' own work; GAI did not generate them.

### How GAI was used, per use case

1. **Feedback on own text / alternative formulations (grammar and language).** The authors' own
   written text (the report and the documentation under `docs/`) was given to the assistant to
   correct grammar, spelling and wording. The assistant's corrections were reviewed and accepted
   or rejected by the authors; the content, structure and claims are the authors'.
2. **Search for information (sources).** The assistant was asked to help find sources and
   references (for example the CWE entries for the four planted vulnerabilities and the PyJWT
   documentation cited in the report). The authors checked the references themselves.
3. **Programming tasks (writing code).** The assistant wrote code from the authors' design: the
   three services (`services/*`), the `exportkit` helper packages (benign and malicious fixture),
   the integrity-gate script, the unit and end-to-end tests, the CLI client, the Dockerfiles /
   docker-compose file and the Jenkinsfile. The authors reviewed the code, ran the test suites and
   the docker-compose environment, and are responsible for it.
4. **Final consistency review (other use case).** Before submission the assistant was asked to
   compare the repository and report with the assignment brief and with the code, and to run the
   tests. This led to concrete corrections that the assistant made and the authors reviewed: the
   Resource Service now enforces the token's `resource` claim (with tests); the `exportkit` wheel
   is verified against the approval manifest before installation in the Dockerfile and the
   Jenkins pipeline (with tests); Experiment B was implemented as written in the brief
   (`scripts/experiment_b.py`, an isolated docker-compose environment and a separate approval
   manifest) and its results saved; the Processing Service container now runs as a non-root user;
   dataset payloads are stored as JSON; a broken `search` command was removed from the CLI client; the
   `artifacts/` folder with saved test and analysis results was added; and statements in the docs
   and the report that did not match the code were corrected (for example the description of what
   the output validation does and does not contain in the supply-chain experiment, the commit
   sequence of the planted vulnerabilities, and the `404` vs `403` behaviour).

### Data protection

No personal or confidential data was given to the assistant. The application uses synthetic,
seeded data only (see `docs/ARCHITECTURE.md`).
