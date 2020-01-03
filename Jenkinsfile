pipeline {
  agent {
    docker {
      image 'golang:buster'
    }

  }
  stages {
    stage('Build') {
      steps {
        sh 'go get gopkg.in/yaml.v2'
        sh 'go build'
      }
    }

    stage('Vet') {
      steps {
        sh 'go vet'
      }
    }

    stage('Test') {
      steps {
        sh 'go test'
      }
    }

  }
}