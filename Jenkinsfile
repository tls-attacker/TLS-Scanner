@Library('jenkins-ci-library@v2') _

standardPipeline(
    enableCentralRelease: true,
    publicRepoUrl: "https://github.com/tls-attacker/TLS-Scanner.git",
    extraStages: {
        // legacy stages
        //     gitHubRelease(
        //             nameApp: 'TLS-Scanner'
        //     )
        releaseDocker.LEGACY_dockerBuild(
            nameApp: 'tlsscanner',
            dockerfile: 'Dockerfile_Jenkins'
        )
        releaseDocker.LEGACY_dockerBuild(
            nameApp: 'tls-crawler',
            dockerfile: 'Dockerfile_Crawler_Jenkins'
        )
    }
)