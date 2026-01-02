

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)
    alias(libs.plugins.kotlin.serialization)
}

group = "io.github.remmerw"
version = "0.5.0"

kotlin {


    androidLibrary {
        namespace = "io.github.remmerw.asen"
        compileSdk = 36
        minSdk = 27



        // Opt-in to enable and configure device-side (instrumented) tests
        withDeviceTest {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
            execution = "ANDROIDX_TEST_ORCHESTRATOR"
        }
    }

    jvm()
    // iosX64()
    // iosArm64()
    // iosSimulatorArm64()
    // linuxArm64()
    // linuxX64()
    // linuxArm64()
    // wasmJs()
    // wasmWasi()
    // js()

    sourceSets {
        commonMain {
            dependencies {
                implementation(libs.kotlin.stdlib)
                implementation(libs.kotlinx.serialization.protobuf)
                implementation(libs.kotlinx.coroutines.core)
                implementation(libs.cryptography.core)
                implementation(libs.hmac.sha2)


                implementation(libs.frey)
                implementation(libs.borr)
            }
        }

        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }

        androidMain {
            dependencies {
                implementation(libs.cryptography.provider.jdk)
            }
        }

        jvmMain {
            dependencies {
                implementation(libs.cryptography.provider.jdk)
            }
        }

    }
}




mavenPublishing {
    publishToMavenCentral()

    signAllPublications()

    coordinates(group.toString(), "asen", version.toString())

    pom {
        name = "asen"
        description = "Basic library for connecting to the libp2p network"
        inceptionYear = "2025"
        url = "https://github.com/remmerw/asen/"
        licenses {
            license {
                name = "The Apache License, Version 2.0"
                url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                distribution = "https://www.apache.org/licenses/LICENSE-2.0.txt"
            }
        }
        developers {
            developer {
                id = "remmerw"
                name = "Remmer Wilts"
                url = "https://github.com/remmerw/"
            }
        }
        scm {
            url = "https://github.com/remmerw/asen/"
            connection = "scm:git:git://github.com/remmerw/asen.git"
            developerConnection = "scm:git:ssh://git@github.com/remmerw/asen.git"
        }
    }
}
