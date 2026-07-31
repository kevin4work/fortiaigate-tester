# ── Network Load Balancer for SSH (port 2222 → 22) ──
# NLB is used instead of ALB because ALB only supports HTTP/HTTPS,
# not raw TCP for SSH forwarding.

resource "aws_lb" "ssh" {
  name               = "${var.project_name}-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets            = [aws_subnet.public.id]

  tags = {
    Name    = "${var.project_name}-nlb"
    Project = var.project_name
  }
}

# NLB target group — targets EC2 on port 22
resource "aws_lb_target_group" "ssh" {
  name        = "${var.project_name}-ssh-tg"
  port        = 22
  protocol    = "TCP"
  vpc_id      = aws_vpc.main.id
  target_type = "instance"

  health_check {
    enabled             = true
    protocol            = "TCP"
    port                = "22"
    interval            = 30
    timeout             = 10
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = {
    Project = var.project_name
  }
}

# NLB listener — listens on port 2222, forwards to target group (port 22)
resource "aws_lb_listener" "ssh" {
  load_balancer_arn = aws_lb.ssh.id
  port              = 2222
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ssh.id
  }

  tags = {
    Project = var.project_name
  }
}

# Attach EC2 instance to the SSH target group
resource "aws_lb_target_group_attachment" "ssh" {
  target_group_arn = aws_lb_target_group.ssh.id
  target_id        = aws_instance.main.id
  port             = 22
}
