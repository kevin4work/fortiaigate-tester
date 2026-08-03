# ── Application Load Balancer ──

resource "aws_lb" "main" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public.id, aws_subnet.public_b.id]

  tags = {
    Name    = "${var.project_name}-alb"
    Project = var.project_name
  }
}

# ── Target Group ──

resource "aws_lb_target_group" "main" {
  name        = "${var.project_name}-tg"
  port        = 8501
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "instance"

  health_check {
    enabled             = true
    path                = "/"
    port                = "8501"
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
    matcher             = "200,302"
  }

  tags = {
    Project = var.project_name
  }
}

# ── ALB Listener (HTTP :80) ──

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.id
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.id
  }

  tags = {
    Project = var.project_name
  }
}
