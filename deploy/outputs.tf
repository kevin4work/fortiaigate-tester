output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = "http://${aws_lb.main.dns_name}"
}

output "ec2_public_ip" {
  description = "Public IP of the EC2 instance"
  value       = aws_instance.main.public_ip
}

output "app_url" {
  description = "URL to access the FortiAIGate attack tester"
  value       = "http://${aws_lb.main.dns_name}"
}
