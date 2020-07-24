# GitHub Actions Tests

**Important Note:** GitHub Actions does *not* recommend self-hosted runners for public repos b/c a PR could trigger arbitrary code execution on the hosted server. However, our tests run in a temporary container that is removed after the test completes, so this mitigates *much* of the risk.