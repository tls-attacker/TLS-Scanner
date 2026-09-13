@Library('jenkins-ci-library') _

standardPipeline(
        jdkTool: 'JDK 21',
        mavenTool: 'Maven 3.9.9',
        spotlessTimeout: 60,
        buildTimeout: 120,
        intTestTimeout: 600,
        codeAnalyseTimeout: 240,
        uniTestTimeout: 180,

        extraStages: {
            gitHubRelease(
                    nameApp: 'TLS-Scanner'
            )
            dockerBuild(
                    nameApp: 'tlsscanner',
                    dockerfile: 'Dockerfile_Jenkins'
            )
            stage('🏷️ Set version') {
                setVersion(projectName: 'tls.scanner')
            }
            stage('🚀 Maven publish central') {
                centralPublish(
                        autoPublish: false,
                        skipTests: true,
                        quiet: false,
                        useSettings: true,
                        settingsId: 'central-settings',
                        profile: '!protocol-attacker,central-release'
                )
            }
        }
)