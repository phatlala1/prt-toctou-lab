// R81 owned security laboratory test injected into the pinned
// microsoft/azure-pipelines-agent test project at runtime.

using System;
using System.Collections.Generic;
using Microsoft.TeamFoundation.DistributedTask.WebApi;
using Microsoft.VisualStudio.Services.Agent.Worker;
using Moq;
using Xunit;

namespace Microsoft.VisualStudio.Services.Agent.Tests.Worker
{
    public sealed class R81FeatureVariableL0
    {
        private const string FeatureVariable =
            "DistributedTask.Tasks.ServiceFabricDeploy.DisableRegistryAuthorityCheck";

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Worker")]
        public void UnrestrictedTaskCanCreateExactServiceFabricKillSwitchVariable()
        {
            using TestHostContext hc = CreateTestContext();

            ExecuteSetVariable(FeatureVariable, "true");

            Assert.Equal("true", _variables.Get(FeatureVariable));
            Assert.False(_variables.IsReadOnly(FeatureVariable));
            Assert.Empty(_warnings);
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Worker")]
        public void ExistingReadOnlyVariableIsStillOverwrittenWhileRolloutKnobIsFalse()
        {
            using TestHostContext hc = CreateTestContext();
            _variables.Set(FeatureVariable, "false", readOnly: true);
            Assert.False(_variables.Read_Only_Variables);

            ExecuteSetVariable(FeatureVariable, "true");

            Assert.Equal("true", _variables.Get(FeatureVariable));
            Assert.True(_variables.IsReadOnly(FeatureVariable));
            Assert.Single(_warnings);
            Assert.Contains("ReadOnly", _warnings[0], StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Worker")]
        public void AgentReadOnlyEnforcementKnobBlocksOverwriteControl()
        {
            using TestHostContext hc = CreateTestContext();
            _variables.Set(FeatureVariable, "false", readOnly: true);
            _variables.Set(Constants.Variables.Agent.ReadOnlyVariables, "true");

            Assert.ThrowsAny<Exception>(() => ExecuteSetVariable(FeatureVariable, "true"));
            Assert.Equal("false", _variables.Get(FeatureVariable));
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Worker")]
        public void ExplicitSettableVariableRestrictionBlocksKillSwitchControl()
        {
            using TestHostContext hc = CreateTestContext();
            _executionContext.Object.Restrictions.Add(
                new TaskRestrictions
                {
                    SettableVariables = new TaskVariableRestrictions(),
                });

            ExecuteSetVariable(FeatureVariable, "true");

            Assert.Null(_variables.Get(FeatureVariable));
            Assert.Single(_warnings);
            Assert.Contains("SetVariableNotAllowed", _warnings[0], StringComparison.Ordinal);
        }

        private void ExecuteSetVariable(string name, string value)
        {
            var command = new Command("task", "setvariable");
            command.Properties.Add("variable", name);
            command.Data = value;
            new TaskSetVariableCommand().Execute(_executionContext.Object, command);
        }

        private TestHostContext CreateTestContext()
        {
            var hc = new TestHostContext(this, nameof(R81FeatureVariableL0));
            hc.SetSingleton(new TaskRestrictionsChecker() as ITaskRestrictionsChecker);

            _variables = new Variables(
                hostContext: hc,
                copy: new Dictionary<string, VariableValue>(),
                warnings: out _);
            _warnings = new List<string>();

            _executionContext = new Mock<IExecutionContext>();
            _executionContext.SetupAllProperties();
            _executionContext.Setup(x => x.Restrictions).Returns(new List<TaskRestrictions>());
            _executionContext.Setup(x => x.GetHostContext()).Returns(hc);
            _executionContext.Setup(x => x.Variables).Returns(_variables);
            _executionContext
                .Setup(x => x.SetVariable(
                    It.IsAny<string>(),
                    It.IsAny<string>(),
                    It.IsAny<bool>(),
                    It.IsAny<bool>(),
                    It.IsAny<bool>(),
                    It.IsAny<bool>(),
                    It.IsAny<bool>()))
                .Callback<string, string, bool, bool, bool, bool, bool>(
                    (name, value, secret, isOutput, isFilePath, readOnly, preserveCase) =>
                        _variables.Set(name, value, secret, readOnly, preserveCase));
            _executionContext
                .Setup(x => x.AddIssue(It.IsAny<Issue>()))
                .Callback<Issue>(issue =>
                {
                    if (issue.Type == IssueType.Warning)
                    {
                        _warnings.Add(issue.Message);
                    }
                });

            return hc;
        }

        private Mock<IExecutionContext> _executionContext = null!;
        private Variables _variables = null!;
        private List<string> _warnings = null!;
    }
}
