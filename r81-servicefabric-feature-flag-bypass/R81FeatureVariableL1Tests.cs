// Licensed to the .NET Foundation under one or more agreements.
// Synthetic R81 owned-lab test. No production secret or external registry is used.

using Microsoft.TeamFoundation.DistributedTask.WebApi;
using System;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
using Pipelines = Microsoft.TeamFoundation.DistributedTask.WebApi;

namespace Microsoft.VisualStudio.Services.Agent.Tests.L1.Worker
{
    [Collection("Worker L1 Tests")]
    public sealed class R81FeatureVariableL1Tests : L1TestBase
    {
        private const string FeatureVariable = "DistributedTask.Tasks.ServiceFabricDeploy.DisableRegistryAuthorityCheck";
        private const string FeatureEnvironment = "DISTRIBUTEDTASK_TASKS_SERVICEFABRICDEPLOY_DISABLEREGISTRYAUTHORITYCHECK";

        [Theory]
        [Trait("Level", "L1")]
        [Trait("Category", "Worker")]
        [InlineData(false)]
        [InlineData(true)]
        public async Task OrdinaryStepCanOverrideFeatureVariableForNextTask(bool writeToBlobstorageService)
        {
            try
            {
                SetupL1();
                var message = LoadTemplateMessage();
                message.Steps.Clear();

                // Model the safe server/default state. This variable is deliberately not marked read-only,
                // matching the agent's current read-only-variable list, which does not contain this feature name.
                message.Variables.Add(FeatureVariable, new Pipelines.VariableValue("false", false, false));
                message.Variables.Add("agent.LogToBlobstorageService", writeToBlobstorageService.ToString());

                // Low-trust pipeline-controlled script output changes the job variable through the shipping
                // logging-command parser. No task extension, server API, PAT, or secret is involved.
                message.Steps.Add(CreateScriptTask(
                    $"echo \"##vso[task.setvariable variable={FeatureVariable}]true\""));

                // The following task observes both macro expansion and the exact normalized environment
                // variable consumed by VstsTaskSdk Get-PipelineFeature.
                message.Steps.Add(CreateScriptTask(
                    $"echo R81_MACRO=$({FeatureVariable}) && echo R81_ENV=%{FeatureEnvironment}%"));

                var results = await RunWorker(message);

                AssertJobCompleted();
                Assert.Equal(TaskResult.Succeeded, results.Result);
                Assert.False(results.TimedOut);

                var steps = GetSteps();
                Assert.Equal(4, steps.Count()); // Initialize, setter, observer, Finalize.

                var setterLog = GetTimelineLogLines(steps[1]);
                Assert.DoesNotContain(setterLog, line =>
                    line.Contains("Can't overwrite read-only variable", StringComparison.OrdinalIgnoreCase));

                var observerLog = GetTimelineLogLines(steps[2]);
                Assert.Contains(observerLog, line =>
                    line.Contains("R81_MACRO=true", StringComparison.OrdinalIgnoreCase));
                Assert.Contains(observerLog, line =>
                    line.Contains("R81_ENV=true", StringComparison.OrdinalIgnoreCase));
                Assert.DoesNotContain(observerLog, line =>
                    line.Contains($"%{FeatureEnvironment}%", StringComparison.OrdinalIgnoreCase));
            }
            finally
            {
                TearDown();
            }
        }
    }
}
