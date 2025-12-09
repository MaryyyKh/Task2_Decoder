plugins {
    kotlin("jvm") version "2.2.21"
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("at.favre.lib:bcrypt:0.10.2")
    implementation("de.mkammerer:argon2-jvm:2.11")
}

kotlin {
    jvmToolchain(21)
}

tasks.test {
    useJUnitPlatform()
}