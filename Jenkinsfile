@Library('jenkins-ci-library') _

standardPipeline(
        buildTimeout: 600,
        testTimeout: 900,

        extraStages: {
            stage('Make Github Release') {
                when {
                    tag 'v*'
                }
                steps {
                    writeFile file: 'release_description.md', text: 'A new version of TLS-Scanner was released. You can download the artifacts (executable .jar) below. \n\n## Changelog:\n  - TODO'
                    sh "zip -r TLS-Scanner-${TAG_NAME}.zip apps"
                    script {
                        def draftRelease = createGitHubRelease(
                                credentialId: '1522a497-e78a-47ee-aac5-70f071fa6714',
                                repository: GIT_URL.tokenize("/.")[-3, -2].join("/"),
                                draft: true,
                                tag: TAG_NAME,
                                name: TAG_NAME,
                                bodyFile: 'release_description.md',
                                commitish: GIT_COMMIT)
                        uploadGithubReleaseAsset(
                                credentialId: '1522a497-e78a-47ee-aac5-70f071fa6714',
                                repository: GIT_URL.tokenize("/.")[-3, -2].join("/"),
                                tagName: draftRelease.htmlUrl.tokenize("/")[-1],
                                uploadAssets: [
                                        [filePath: "TLS-Scanner-${TAG_NAME}.zip"]
                                ]
                        )
                    }
                }
            }
            stage('Public Docker Images') {
                when {
                    tag 'v*'
                    environment name: 'GIT_URL', value: 'https://github.com/tls-attacker/TLS-Scanner.git'
                }
                steps {
                    script {
                        docker.withRegistry('https://ghcr.io', 'github-docker-token') {
                            def image = docker.build("ghcr.io/tls-attacker/tlsscanner:${TAG_NAME}", "-f Dockerfile_Jenkins .")
                            image.push()
                            image.push('latest')
                        }
                    }
                }
            }
            stage('Internal Docker Images') {
                when {
                    tag 'v*'
                    environment name: 'GIT_URL', value: 'https://github.com/tls-attacker/TLS-Scanner-Development.git'
                }
                steps {
                    script {
                        docker.withRegistry('https://hydrogen.cloud.nds.rub.de', 'Jenkins-User-Nexus-Repository') {
                            def image = docker.build("hydrogen.cloud.nds.rub.de/tls-attacker/tlsscanner:${TAG_NAME}", "-f Dockerfile_Jenkins .")
                            image.push()
                            image.push('latest')
                        }
                    }
                }
            }
        }
)