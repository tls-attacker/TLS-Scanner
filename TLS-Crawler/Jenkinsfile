@Library('jenkins-ci-library') _

standardPipeline(
        jdkTool: 'JDK 21',
        mavenTool: 'Maven 3.9.9',
        spotlessTimeout: 60,
        buildTimeout: 120,
        intTestTimeout: 1800,
        codeAnalyseTimeout: 240,
        uniTestTimeout: 180,
        archiveArtifacts: true,
        archivePattern: '**/target/*.jar',

        extraStages: {
            dockerBuildSH(
                    nameApp: 'tls-crawler',
                    stashes: ['jar', 'lib'],
                    elasticApmVersion: '1.38.0'
            )
        }
)