<p align="left">
  <img src="https://step-security-images.s3.us-west-2.amazonaws.com/Final-Logo-06.png" alt="Step Security Logo" width="340">
</p>

# Step Security Agent [![codecov](https://codecov.io/gh/step-security/agent/branch/main/graph/badge.svg?token=V9M3GASVYP)](https://codecov.io/gh/step-security/agent)

Purpose-built security agent for hosted runners

To pilot it, add the following code to your GitHub Actions workflow file as the first step. This is the only step needed.

```
steps:
    - uses: step-security/harden-runner@main
```

In the workflow logs, you should see a link to security insights and recommendations.

It is being piloted on this repository. Check out the workflow files and workflow runs.


