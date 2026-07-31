output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer (HTTP)"
  value       = "http://${aws_lb.main.dns_name}"
}

output "app_url" {
  description = "URL to access the FortiAIGate attack tester"
  value       = "http://${aws_lb.main.dns_name}"
}

output "ec2_public_ip" {
  description = "Public IP of the EC2 instance (for reference only — SSH not directly accessible)"
  value       = aws_instance.main.public_ip
}

output "ssh_nlb_dns" {
  description = "DNS name of the NLB for SSH access on port 2222"
  value       = aws_lb.ssh.dns_name
}

output "ssh_command" {
  description = "SSH command to connect to the EC2 instance via NLB"
  value       = "ssh -i ~/.ssh/aws-demo-us-west-2.pem -p 2222 ec2-user@${aws_lb.ssh.dns_name}"
}
