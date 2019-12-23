pipeline {
  agent {
    docker {
      image 'golang:buster'
    }

  }
  stages {
    stage('Build') {
      steps {
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