@Library('jenkins-ci-library') _

standardPipeline(
        buildTimeout: 600,
        testTimeout: 900,

        extraStages: {
            gitHubRelease()
            dockerBuild()
        }
)