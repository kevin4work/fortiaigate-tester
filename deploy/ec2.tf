# ── EC2 Instance ──

# Find the latest Amazon Linux 2023 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Read the user_data script
locals {
  user_data = file("${path.module}/user_data.sh")
}

resource "aws_instance" "main" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = var.instance_type
  key_name                    = var.key_name
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.ec2.id]
  user_data                   = local.user_data
  user_data_replace_on_change = true

  root_block_device {
    volume_size = 10
    volume_type = "gp3"
  }

  tags = {
    Name    = "${var.project_name}-ec2"
    Project = var.project_name
  }
}

# ── Target Group Attachment ──

resource "aws_lb_target_group_attachment" "main" {
  target_group_arn = aws_lb_target_group.main.id
  target_id        = aws_instance.main.id
  port             = 8501
}
