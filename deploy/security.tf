# ── Security Groups ──

# ALB security group — allow HTTP from anywhere
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "Allow HTTP inbound to ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-alb-sg"
    Project = var.project_name
  }
}

# NLB security group — allow SSH (2222) from anywhere
resource "aws_security_group" "nlb" {
  name        = "${var.project_name}-nlb-sg"
  description = "Allow SSH (2222) inbound to NLB"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 2222
    to_port     = 2222
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-nlb-sg"
    Project = var.project_name
  }
}

# EC2 security group — allow 8501 from ALB, 22 only from NLB
resource "aws_security_group" "ec2" {
  name        = "${var.project_name}-ec2-sg"
  description = "Allow Streamlit (8501) from ALB and SSH (22) only from NLB"
  vpc_id      = aws_vpc.main.id

  # Streamlit port from ALB security group
  ingress {
    from_port       = 8501
    to_port         = 8501
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # SSH from VPC CIDR — NLB forwards traffic from its node IPs within the VPC
  # (NLBs don't attach security groups, so we can't reference an NLB SG here)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-ec2-sg"
    Project = var.project_name
  }
}
